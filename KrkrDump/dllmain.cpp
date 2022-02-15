// dllmain.cpp

#include "util.h"
#include "path.h"
#include "log.h"
#include "pe.h"
#include "stringhelper.h"
#include "file.h"
#include "encoding.h"
#include "detours.h"
#include "cJSON.h"
#include "zlib.h"
#include <regex>
#include <vector>
#include <shlobj.h>

#pragma warning ( push )
#pragma warning ( disable : 4100 4201 4457 )
#include "tp_stub.h"
#pragma warning ( pop )


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

		PVOID pfnTVPCreateIStream = TVPGetImportFuncPtr("IStream * ::TVPCreateIStream(const ttstr &,tjs_uint32)");

		g_logger.WriteLine(L"Caught TVPCreateIStream(%p)", pfnTVPCreateIStream);
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

static bool g_decryptSimpleCrypt;


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


bool TryDecryptText(tTJSBinaryStream* stream, std::vector<uint8_t>& output)
{
	try
	{
		uint8_t mark[2];

		memset(mark, 0, sizeof(mark));
		stream->Read(mark, 2);

		if (mark[0] == 0xfe && mark[1] == 0xfe)
		{
			uint8_t mode;

			stream->Read(&mode, 1);

			if (mode != 0 && mode != 1 && mode != 2)
			{
				return false;
			}

			memset(mark, 0, sizeof(mark));
			stream->Read(mark, 2);

			if (mark[0] != 0xff || mark[1] != 0xfe)
			{
				return false;
			}

			if (mode == 2)
			{
				tjs_int64 compressed = 0;
				tjs_int64 uncompressed = 0;

				stream->Read(&compressed, sizeof(tjs_int64));
				stream->Read(&uncompressed, sizeof(tjs_int64));

				if (compressed <= 0 || compressed >= INT_MAX || uncompressed <= 0 || uncompressed >= INT_MAX)
				{
					return false;
				}

				std::vector<uint8_t> data((size_t)compressed);

				if (stream->Read(data.data(), (tjs_uint)compressed) != compressed)
				{
					return false;
				}

				size_t count = (size_t)uncompressed;

				std::vector<uint8_t> buffer(count + 2);

				buffer[0] = mark[0];
				buffer[1] = mark[1];

				Bytef* dest = buffer.data() + 2;
				uLongf destLen = (uLongf)uncompressed;

				int result = Z_OK;

				try
				{
					result = uncompress(dest, &destLen, data.data(), (uLong)compressed);
				}
				catch (...)
				{
					return false;
				}

				if (result != Z_OK || destLen != (uLongf)uncompressed)
				{
					return false;
				}

				output = std::move(buffer);

				return true;
			}
			else
			{
				tjs_int64 startpos = (tjs_int64)stream->Seek(0, TJS_BS_SEEK_CUR);
				tjs_int64 endpos = (tjs_int64)stream->Seek(0, TJS_BS_SEEK_END);

				stream->Seek(startpos, TJS_BS_SEEK_SET);

				tjs_int64 size = endpos - startpos;

				if (size <= 0 || size >= INT_MAX)
				{
					return false;
				}

				size_t count = (size_t)(size / sizeof(tjs_char));

				if (count == 0)
				{
					return false;
				}

				std::vector<tjs_char> buffer(count);

				tjs_uint sizeToRead = (tjs_uint)size;

				stream->Read(buffer.data(), sizeToRead);

				if (mode == 0)
				{
					for (size_t i = 0; i < count; i++)
					{
						tjs_char ch = buffer[i];
						if (ch >= 0x20) buffer[i] = ch ^ (((ch & 0xfe) << 8) ^ 1);
					}
				}
				else if (mode == 1)
				{
					for (size_t i = 0; i < count; i++)
					{
						tjs_char ch = buffer[i];
						ch = ((ch & 0xaaaaaaaa) >> 1) | ((ch & 0x55555555) << 1);
						buffer[i] = ch;
					}
				}

				size_t sizeToCopy = count * sizeof(tjs_char);

				output.resize(sizeToCopy + 2);

				output[0] = mark[0];
				output[1] = mark[1];

				memcpy(output.data() + 2, buffer.data(), sizeToCopy);

				return true;
			}
		}
	}
	catch (...)
	{
	}

	return false;
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
		std::vector<uint8_t> buffer;

		bool success = false;

		if (g_decryptSimpleCrypt && TryDecryptText(stream, buffer))
		{
			success = true;
		}
		else
		{
			buffer.resize(size);

			stream->Seek(0, TJS_BS_SEEK_SET);

			if (stream->Read(buffer.data(), size) == size)
			{
				success = true;
			}
		}

		if (success && !buffer.empty())
		{
			if (g_logLevel > 0)
				g_logger.WriteLine(L"Extract \"%s\"", extractPath.c_str());

			if (File::WriteAllBytes(outputPath, buffer.data(), buffer.size()) == false)
			{
				g_logger.WriteLine(L"Failed to write \"%s\"", outputPath.c_str());
			}
		}

		stream->Seek(0, TJS_BS_SEEK_SET);
	}
	else
	{
		File::WriteAllBytes(outputPath, NULL, 0);
	}
}


void ProcessStream(tTJSBinaryStream* stream, ttstr* name, tjs_uint32 flags)
{
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
}


// 
// Version : KRKRZ (MSVC)
// 
#define TVPCREATESTREAM_SIG "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x64\xA1\x2A\x2A\x2A\x2A\x50\x83\xEC\x5C\x53\x56\x57\xA1\x2A\x2A\x2A\x2A\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x2A\x2A\x2A\x2A\x89\x65\xF0\x89\x4D\xEC\xC7\x45\x2A\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\x8B\x4D\xF4\x64\x89\x0D\x2A\x2A\x2A\x2A\x59\x5F\x5E\x5B\x8B\xE5\x5D\xC3"
#define TVPCREATESTREAM_SIG_LEN ( sizeof(TVPCREATESTREAM_SIG) - 1 )
// Prototype
typedef tTJSBinaryStream* (_fastcall* tKrkrzMsvcFastCallTVPCreateStreamProc)(ttstr*, tjs_uint32);


//
// Version : KRKR2 (BCB)
//
#define KR2_TVPCREATESTREAM_SIG "\x55\x8B\xEC\x81\xC4\x2A\x2A\x2A\x2A\x53\x56\x57\x89\x95\x2A\x2A\x2A\x2A\x89\x85\x2A\x2A\x2A\x2A\xB8\x2A\x2A\x2A\x2A\xC7\x85\x2A\x2A\x2A\x2A\x2A\x2A\x2A\x2A\x89\x65\x80\x89\x85\x2A\x2A\x2A\x2A\x66\xC7\x45\x2A\x2A\x2A\x33\xD2\x89\x55\x90\x64\x8B\x0D\x2A\x2A\x2A\x2A\x89\x8D\x2A\x2A\x2A\x2A\x8D\x85\x2A\x2A\x2A\x2A\x64\xA3\x2A\x2A\x2A\x2A\x66\xC7\x45\x2A\x2A\x2A\x8B\x95\x2A\x2A\x2A\x2A\x8B\x85\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\x8B\x95\x2A\x2A\x2A\x2A\x64\x89\x15\x2A\x2A\x2A\x2A\xE9\x2A\x2A\x2A\x2A\x6A\x23\x8B\x8D\x2A\x2A\x2A\x2A\x83\x39\x00\x74\x20\x8B\x85\x2A\x2A\x2A\x2A\x8B\x00\x85\xC0\x75\x04\x33\xD2"
#define KR2_TVPCREATESTREAM_SIG_LEN ( sizeof(KR2_TVPCREATESTREAM_SIG) - 1 )


// Original
tKrkrzMsvcFastCallTVPCreateStreamProc pfnKrkrzMsvcFastCallTVPCreateStreamProc;
// Hooked
tTJSBinaryStream* _fastcall KrkrzMsvcFastCallTVPCreateStream(ttstr* name, tjs_uint32 flags)
{
	tTJSBinaryStream* stream = pfnKrkrzMsvcFastCallTVPCreateStreamProc(name, flags);
	ProcessStream(stream, name, flags);
	return stream;
}


// Original
PVOID pfnKrkr2BcbFastCallTVPCreateStreamProc;
// Callback
_declspec(naked)
tTJSBinaryStream* Krkr2BcbFastCallTVPCreateStreamCallback(ttstr* name, tjs_uint32 flags)
{
	_asm
	{
		mov edx, flags
		mov eax, name
		call pfnKrkr2BcbFastCallTVPCreateStreamProc
		ret
	}
}
// Hooked
tTJSBinaryStream* Krkr2BcbFastCallTVPCreateStream(ttstr* name, tjs_uint32 flags)
{
	tTJSBinaryStream* stream = Krkr2BcbFastCallTVPCreateStreamCallback(name, flags);
	ProcessStream(stream, name, flags);
	return stream;
}
// Detour
_declspec(naked)
void Krkr2BcbFastCallTVPCreateStreamDetour()
{
	_asm
	{
		push edx
		push eax
		call Krkr2BcbFastCallTVPCreateStream
		add esp, 8
		ret
	}
}


void LoadConfiguration()
{
	g_logLevel = 0;
	g_enableExtract = false;
	g_outputPath.clear();
	g_regexRules.clear();
	g_includeExtensions.clear();
	g_excludeExtensions.clear();
	g_decryptSimpleCrypt = false;

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

		cJSON* jDecrypt = cJSON_GetObjectItem(jRoot, "decryptSimpleCrypt");

		if (jDecrypt)
		{
			g_decryptSimpleCrypt = cJSON_IsTrue(jDecrypt);
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

	g_logger.WriteLine(L"Image Base = %p", base);
	g_logger.WriteLine(L"Image Base = %X", size);

	PVOID pfnTVPCreateStream = PE::SearchPattern(base, size, TVPCREATESTREAM_SIG, TVPCREATESTREAM_SIG_LEN);

	if (pfnTVPCreateStream)
	{
		pfnKrkrzMsvcFastCallTVPCreateStreamProc = (tKrkrzMsvcFastCallTVPCreateStreamProc)pfnTVPCreateStream;

		InlineHook(pfnKrkrzMsvcFastCallTVPCreateStreamProc, KrkrzMsvcFastCallTVPCreateStream);

		g_logger.WriteLine(L"KrKrZ Hooks Installed");
	}
	else
	{
		pfnTVPCreateStream = PE::SearchPattern(base, size, KR2_TVPCREATESTREAM_SIG, KR2_TVPCREATESTREAM_SIG_LEN);

		if (pfnTVPCreateStream)
		{
			pfnKrkr2BcbFastCallTVPCreateStreamProc = pfnTVPCreateStream;

			DetourUpdateThread(GetCurrentThread());
			DetourTransactionBegin();
			DetourAttach(&pfnKrkr2BcbFastCallTVPCreateStreamProc, Krkr2BcbFastCallTVPCreateStreamDetour);
			DetourTransactionCommit();

			g_logger.WriteLine(L"KrKr2 Hooks Installed");
		}
	}

#ifdef FIND_EXPORTER
	InlineHook(pfnGetProcAddress, HookGetProcAddress);
#endif
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
