// dllmain.cpp

#include "util.h"
#include "path.h"
#include "log.h"
#include "pe.h"
#include "stringhelper.h"
#include "file.h"
#include "encoding.h"
#include "detours.h"
#include "tp_stub.h"
#include "cJSON.h"
#include <regex>
#include <vector>
#include <shlobj.h>


static HMODULE g_hEXE;
static HMODULE g_hDLL;

static std::wstring g_exePath;
static std::wstring g_dllPath;

static Log::Logger g_logger;

static int g_logLevel;


template<class T>
void InlineHook(T& OriginalFunction, T DetourFunction)
{
	DetourUpdateThread(GetCurrentThread());
	DetourTransactionBegin();
	DetourAttach(&(PVOID&)OriginalFunction, (PVOID&)DetourFunction);
	DetourTransactionCommit();
}


template<class T>
void UnInlineHook(T& OriginalFunction, T DetourFunction)
{
	DetourUpdateThread(GetCurrentThread());
	DetourTransactionBegin();
	DetourDetach(&(PVOID&)OriginalFunction, (PVOID&)DetourFunction);
	DetourTransactionCommit();
}


#ifdef FIND_EXPORTER


extern "C"
{
	typedef HRESULT(_stdcall* tTVPV2LinkProc)(iTVPFunctionExporter*);
	typedef HRESULT(_stdcall* tTVPV2UnlinkProc)();
}

static iTVPFunctionExporter* TVPFunctionExporter;


// Original
tTVPV2LinkProc pfnV2Link;
// Hooked
HRESULT _stdcall HookV2Link(iTVPFunctionExporter* exporter)
{
	try
	{
		TVPFunctionExporter = exporter;

		g_logger.WriteLine(L"Caught iTVPFunctionExporter(%p)", exporter);

		TVPInitImportStub(exporter);

		g_logger.WriteLine(L"Stub initialized");
	}
	catch (const std::exception& e)
	{
		g_logger.WriteLineAnsi(CP_ACP, "Failed to initialize stub, %s", e.what());
	}

	HRESULT result = pfnV2Link(exporter);

	try
	{
		// We don't need it anymore
		UnInlineHook(pfnV2Link, HookV2Link);
	}
	catch (const std::exception&)
	{
	}

	return result;
}


// Original
auto pfnGetProcAddress = GetProcAddress;
// Hooked
FARPROC WINAPI HookGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	FARPROC result = pfnGetProcAddress(hModule, lpProcName);

	try
	{
		if (result)
		{
			// Ignore function imported by ordinal
			if (HIWORD(lpProcName) != 0)
			{
				if (strcmp(lpProcName, "V2Link") == 0)
				{
					pfnV2Link = (tTVPV2LinkProc)result;

					// We don't need it anymore
					UnInlineHook(pfnGetProcAddress, HookGetProcAddress);

					auto path = Util::GetModulePathW(hModule);
					auto name = Path::GetFileName(path);

					g_logger.WriteLine(L"Caught V2Link(%p) from %s(%p)", result, name.c_str(), hModule);

					// Now hook V2Link to get iTVPFunctionExporter

					InlineHook(pfnV2Link, HookV2Link);

					g_logger.WriteLine(L"Hook V2Link installed");
				}
			}
		}
	}
	catch (const std::exception& e)
	{
		g_logger.WriteLineAnsi(CP_ACP, "Failed to hook V2Link, %s", e.what());
	}

	return result;
}


#endif


const tjs_char* TJSStringGetPtr(tTJSString* s)
{
	if (!s)
		return L"";

	tTJSVariantString_S* v = *(tTJSVariantString_S**)s;

	if (!v)
		return L"";

	if (v->LongString)
		return v->LongString;

	return v->ShortString;
}


class tTJSBinaryStream
{
public:
	virtual tjs_uint64 TJS_INTF_METHOD Seek(tjs_int64 offset, tjs_int whence) = 0;
	virtual tjs_uint TJS_INTF_METHOD Read(void* buffer, tjs_uint read_size) = 0;
	// virtual tjs_uint TJS_INTF_METHOD Write(const void* buffer, tjs_uint write_size) = 0;
	// virtual void TJS_INTF_METHOD SetEndOfStorage() = 0;
	// virtual tjs_uint64 TJS_INTF_METHOD GetSize() = 0;
	// virtual ~tTJSBinaryStream() { }
};

static bool g_enableExtract;

static std::wstring g_outputPath;

static std::vector<std::wstring> g_regexRules;

static std::vector<std::wstring> g_includeExtensions;
static std::vector<std::wstring> g_excludeExtensions;


std::wstring MatchPath(const std::wstring& path)
{
	std::wstring newPath;

	if (path.find(L':') != std::string::npos)
	{
		for (auto& rule : g_regexRules)
		{
			std::wregex expr(rule, std::regex_constants::icase);
			std::wsmatch result;

			if (std::regex_match(path, result, expr))
			{
				if (result.size() > 1)
					newPath = result[1].str();
				else
					newPath = result[0].str();
			}
		}
	}
	else
	{
		newPath = path;
	}

	if (!g_includeExtensions.empty())
	{
		std::wstring ext = Path::GetExtension(newPath);

		if (!ext.empty())
		{
			std::wstring l = StringHelper::ToLower(ext);

			bool found = false;

			for (auto& e : g_includeExtensions)
			{
				if (l == e)
				{
					found = true;
					break;
				}
			}

			if (!found)
			{
				newPath.clear();
			}
		}
	}
	else if (!g_excludeExtensions.empty())
	{
		std::wstring ext = Path::GetExtension(newPath);

		if (!ext.empty())
		{
			std::wstring l = StringHelper::ToLower(ext);

			for (auto& e : g_excludeExtensions)
			{
				if (l == e)
				{
					newPath.clear();
					break;
				}
			}
		}
	}

	return newPath;
}


void FixPath(std::wstring& path)
{
	for (size_t i = 0; i < path.length(); i++)
	{
		if (path[i] == L'/')
		{
			path[i] = L'\\';
		}
	}
}


tjs_uint64 TJSBinaryStream_GetLength(tTJSBinaryStream* stream)
{
	tjs_uint64 size;

	size = stream->Seek(0, TJS_BS_SEEK_END);
	stream->Seek(0, TJS_BS_SEEK_SET);

	return size;
}


void ExtractFile(tTJSBinaryStream* stream, std::wstring& extractPath)
{
	FixPath(extractPath);

	if (StringHelper::StartsWith(extractPath, L".\\"))
	{
		extractPath = extractPath.substr(2);
	}

	std::wstring outputPath = g_outputPath + extractPath;

	// Create output directory

	std::wstring outputDir = Path::GetDirectoryName(outputPath);

	if (!outputDir.empty())
	{
		SHCreateDirectory(NULL, outputDir.c_str());
	}

	// Write to file

	size_t size = (size_t)TJSBinaryStream_GetLength(stream);

	if (size > 0)
	{
		std::vector<uint8_t> buffer(size);

		if (stream->Read(buffer.data(), size) == size)
		{
			if (g_logLevel > 0)
				g_logger.WriteLine(L"Extract \"%s\"", extractPath.c_str());

			if (File::WriteAllBytes(outputPath, buffer.data(), size) == false)
			{
				g_logger.WriteLine(L"Failed to write \"%s\"", outputPath.c_str());
			}
		}

		// Back to head
		stream->Seek(0, TJS_BS_SEEK_SET);
	}
	else
	{
		File::WriteAllBytes(outputPath, NULL, 0);
	}
}


// 
// Version : KRKRZ (MSVC)
// 
#define TVPCREATESTREAM_SIG "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x64\xA1\x2A\x2A\x2A\x2A\x50\x83\xEC\x5C\x53\x56\x57\xA1\x2A\x2A\x2A\x2A\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x2A\x2A\x2A\x2A\x89\x65\xF0\x89\x4D\xEC\xC7\x45\x2A\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\x8B\x4D\xF4\x64\x89\x0D\x2A\x2A\x2A\x2A\x59\x5F\x5E\x5B\x8B\xE5\x5D\xC3"
#define TVPCREATESTREAM_SIG_LEN ( sizeof(TVPCREATESTREAM_SIG) - 1 )
// Prototype
typedef tTJSBinaryStream* (_fastcall* tKrkrzMsvcFastCallTVPCreateStreamProc)(ttstr*, tjs_uint32);


// Original
tKrkrzMsvcFastCallTVPCreateStreamProc pfnKrkrzMsvcFastCallTVPCreateStreamProc;
// Hooked
tTJSBinaryStream* _fastcall KrkrzMsvcFastCallTVPCreateStream(ttstr* name, tjs_uint32 flags)
{
	tTJSBinaryStream* stream = pfnKrkrzMsvcFastCallTVPCreateStreamProc(name, flags);

	if (stream && flags == TJS_BS_READ)
	{
		try
		{
			const tjs_char* psz = TJSStringGetPtr(name);

			std::wstring path(psz);

			std::wstring extractPath = MatchPath(path);

			if (!extractPath.empty())
			{
				if (g_logLevel > 1)
					g_logger.WriteLine(L"Included \"%s\"", psz);

				if (g_enableExtract)
				{
					ExtractFile(stream, extractPath);
				}
			}
			else
			{
				if (g_logLevel > 1)
					g_logger.WriteLine(L"Excluded \"%s\"", psz);
			}
		}
		catch (const std::exception& e)
		{
			g_logger.WriteLineAnsi(CP_ACP, "Exception : %s", e.what());
		}
	}

	return stream;
}


void LoadConfiguration()
{
	g_logLevel = 0;
	g_enableExtract = false;
	g_outputPath.clear();
	g_regexRules.clear();
	g_includeExtensions.clear();
	g_excludeExtensions.clear();

	std::wstring jsonPath = Path::ChangeExtension(g_dllPath, L"json");
	std::string json = File::ReadAllText(jsonPath);

	cJSON* jRoot = cJSON_Parse(json.c_str());

	if (jRoot)
	{
		cJSON* jLogLevel = cJSON_GetObjectItem(jRoot, "logLevel");

		if (jLogLevel)
		{
			g_logLevel = (int)cJSON_GetNumberValue(jLogLevel);
		}

		cJSON* jEnable = cJSON_GetObjectItem(jRoot, "enableExtract");

		if (jEnable)
		{
			g_enableExtract = cJSON_IsTrue(jEnable);
		}

		cJSON* jOutputPath = cJSON_GetObjectItem(jRoot, "outputDirectory");

		if (jOutputPath)
		{
			char* value = cJSON_GetStringValue(jOutputPath);

			if (value)
			{
				g_outputPath = Encoding::AnsiToUnicode(value, Encoding::UTF_8);

				if (!g_outputPath.empty())
				{
					FixPath(g_outputPath);

					if (g_outputPath.back() != L'\\')
					{
						g_outputPath += L'\\';
					}

					g_logger.WriteLine(L"Output Directory Path = \"%s\"", g_outputPath.c_str());
				}
				else
				{
					g_enableExtract = false;

					g_logger.WriteLine(L"No output directory set, extraction disabled.");
				}
			}
		}

		cJSON* jRules = cJSON_GetObjectItem(jRoot, "rules");

		if (jRules)
		{
			if (cJSON_IsArray(jRules))
			{
				int count = cJSON_GetArraySize(jRules);

				for (int i = 0; i < count; i++)
				{
					cJSON* jItem = cJSON_GetArrayItem(jRules, i);

					if (jItem)
					{
						char* value = cJSON_GetStringValue(jItem);

						if (value)
						{
							std::wstring rule = Encoding::AnsiToUnicode(value, Encoding::UTF_8);

							if (rule.empty())
							{
								continue;
							}

							g_regexRules.push_back(rule);
						}
					}
				}
			}
		}

		cJSON* jIncludeExt = cJSON_GetObjectItem(jRoot, "includeExtensions");

		if (jIncludeExt)
		{
			if (cJSON_IsArray(jIncludeExt))
			{
				int count = cJSON_GetArraySize(jIncludeExt);

				for (int i = 0; i < count; i++)
				{
					cJSON* jItem = cJSON_GetArrayItem(jIncludeExt, i);

					if (jItem)
					{
						char* value = cJSON_GetStringValue(jItem);

						if (value)
						{
							std::wstring ext = Encoding::AnsiToUnicode(value, Encoding::UTF_8);

							if (ext.empty())
							{
								continue;
							}

							g_includeExtensions.push_back(StringHelper::ToLower(ext));
						}
					}
				}
			}
		}

		cJSON* jExcludeExt = cJSON_GetObjectItem(jRoot, "excludeExtensions");

		if (jExcludeExt)
		{
			if (cJSON_IsArray(jExcludeExt))
			{
				int count = cJSON_GetArraySize(jExcludeExt);

				for (int i = 0; i < count; i++)
				{
					cJSON* jItem = cJSON_GetArrayItem(jExcludeExt, i);

					if (jItem)
					{
						char* value = cJSON_GetStringValue(jItem);

						if (value)
						{
							std::wstring ext = Encoding::AnsiToUnicode(value, Encoding::UTF_8);

							if (ext.empty())
							{
								continue;
							}

							g_excludeExtensions.push_back(StringHelper::ToLower(ext));
						}
					}
				}
			}
		}

		cJSON_Delete(jRoot);
	}

	for (auto& s : g_regexRules)
	{
		g_logger.WriteLine(L"Loaded rule \"%s\"", s.c_str());
	}
}


void InstallHooks()
{
	PVOID base = PE::GetModuleBase(g_hEXE);
	DWORD size = PE::GetModuleSize(g_hEXE);

	PVOID pfnTVPCreateStream = PE::SearchPattern(base, size, TVPCREATESTREAM_SIG, TVPCREATESTREAM_SIG_LEN);

	if (pfnTVPCreateStream)
	{
		pfnKrkrzMsvcFastCallTVPCreateStreamProc = (tKrkrzMsvcFastCallTVPCreateStreamProc)pfnTVPCreateStream;

		InlineHook(pfnKrkrzMsvcFastCallTVPCreateStreamProc, KrkrzMsvcFastCallTVPCreateStream);
	}

	// InlineHook(pfnGetProcAddress, HookGetProcAddress);
}


void OnStartup()
{
	std::wstring exePath = Util::GetModulePathW(g_hEXE);
	std::wstring dllPath = Util::GetModulePathW(g_hDLL);
	std::wstring logPath = Path::ChangeExtension(dllPath, L"log");
	std::wstring cfgPath = Path::ChangeExtension(dllPath, L"json");

	Util::WriteDebugMessage(L"[KrkrDump] EXE Path = \"%s\"", exePath.c_str());
	Util::WriteDebugMessage(L"[KrkrDump] DLL Path = \"%s\"", dllPath.c_str());
	Util::WriteDebugMessage(L"[KrkrDump] Log Path = \"%s\"", logPath.c_str());
	Util::WriteDebugMessage(L"[KrkrDump] Cfg Path = \"%s\"", logPath.c_str());

	// !!!
	File::Delete(logPath);

	g_logger.Open(logPath.c_str());

	g_logger.WriteLine(L"Startup");

	g_logger.WriteLine(L"Game Executable Path = \"%s\"", exePath.c_str());

	g_exePath = std::move(exePath);
	g_dllPath = std::move(dllPath);

	// Started

	try
	{
		LoadConfiguration();

		g_logger.WriteLine(L"Configuration loaded");
	}
	catch (const std::exception&)
	{
		g_logger.WriteLine(L"Failed to load configuration");
	}

	try
	{
		InstallHooks();

		g_logger.WriteLine(L"Hooks Installed");
	}
	catch (const std::exception&)
	{
		g_logger.WriteLine(L"Failed to install hooks");
	}
}


void OnShutdown()
{
	g_logger.WriteLine(L"Shutdown");
	g_logger.Close();
}


// Create export function table.
extern "C" __declspec(dllexport) BOOL CreatePlugin() { return TRUE; }


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	UNREFERENCED_PARAMETER(lpReserved);

	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		{
			g_hEXE = GetModuleHandle(NULL);
			g_hDLL = hModule;
			OnStartup();
			break;
		}
		case DLL_THREAD_ATTACH:
		{
			break;
		}
		case DLL_THREAD_DETACH:
		{
			break;
		}
		case DLL_PROCESS_DETACH:
		{
			OnShutdown();
			break;
		}
	}

	return TRUE;
}