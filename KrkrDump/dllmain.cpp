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
#include <unordered_set>
#include <shlobj.h>

#pragma warning ( push )
#pragma warning ( disable : 4100 4201 4457 )
#include "tp_stub.h"
#pragma warning ( pop )

#undef min
#undef max

static HMODULE g_hEXE;
static HMODULE g_hDLL;

static std::wstring g_exePath;
static std::wstring g_dllPath;

static Log::Logger g_logger;

static int g_logLevel;
static bool g_truncateLog;
static bool g_tvpStubInitialized = false;


#define FIND_EXPORTER
#define DUMP_HASH
#define DUMP_HXKEY
#define PATCH_SBEAM
#define PATCH_SIGNATURECHECK


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


#ifdef DUMP_HASH


#define PATHHASHSIG "\x55\x8B\xEC\x83\xEC\x50\xFF\x71\x08\xC7\x45\x2A\x2A\x2A\x2A\x2A\xFF\x71\x04\x8D\x4D\xB0"
#define PATHHASHSIG_LEN ( sizeof(PATHHASHSIG) - 1 )


#define NAMEHASHSIG "\x55\x8B\xEC\x81\xEC\x2A\x2A\x2A\x2A\xA1\x2A\x2A\x2A\x2A\x33\xC5\x89\x45\xFC\x8B\x45\x08\x56\x8B\x75\x10\x57"
#define NAMEHASHSIG_LEN ( sizeof(NAMEHASHSIG) - 1 )


class Hasher;
typedef int (Hasher::*ComputeHashProc)(tTJSVariant*, tTJSString*, tTJSString*);


ComputeHashProc pfnComputePathName = NULL;
ComputeHashProc pfnComputeFileName = NULL;


static bool g_enableDumpHash = false;


void PrintHexString(wchar_t* _Buf, size_t _BufSize, const void* _Data, size_t _Size)
{
	auto _Ptr = _Buf;
	auto _End = _Buf + _BufSize;
	auto _In = (byte*)_Data;

	if (!_Buf || !_BufSize || !_Data || !_Size)
		return;

	for (size_t i = 0; i < _Size; i++)
	{
		if (_Ptr + 3 > _End)
			break;
		swprintf(_Ptr, L"%02X", _In[i]);
		_Ptr += 2;
	}
}


std::unordered_set<std::wstring> g_pathHashSet;
std::unordered_set<std::wstring> g_nameHashSet;


class Hasher
{
public:
	int ComputePathName(tTJSVariant* hash, tTJSString* input, tTJSString* salt)
	{
		int result = (this->*pfnComputePathName)(hash, input, salt);

		if (g_tvpStubInitialized && hash && hash->Type() == tvtOctet)
		{
			auto octet = hash->AsOctetNoAddRef();

			if (octet)
			{
				wchar_t buffer[80] {};
				
				PrintHexString(buffer, _countof(buffer), octet->GetData(), octet->GetLength());

				auto ret = g_pathHashSet.insert(buffer);

				if (ret.second)
				{
					g_logger.WriteLine(L"PathHash: \"%s\" \"%s\" \"%s\"", input->c_str(), salt->c_str(), buffer);
				}
			}
		}

		return result;
	}

	int ComputeFileName(tTJSVariant* hash, tTJSString* input, tTJSString* salt)
	{
		int result = (this->*pfnComputeFileName)(hash, input, salt);

		if (g_tvpStubInitialized && hash && hash->Type() == tvtOctet)
		{
			auto octet = hash->AsOctetNoAddRef();

			if (octet)
			{
				wchar_t buffer[80] {};

				PrintHexString(buffer, _countof(buffer), octet->GetData(), octet->GetLength());

				auto ret = g_nameHashSet.insert(buffer);

				if (ret.second)
				{
					g_logger.WriteLine(L"NameHash: \"%s\" \"%s\" \"%s\"", input->c_str(), salt->c_str(), buffer);
				}
			}
		}

		return result;
	}
};


void HookHash(HMODULE hModule)
{
	PVOID base = PE::GetModuleBase(hModule);
	DWORD size = PE::GetModuleSize(hModule);

	*(PVOID*)&pfnComputePathName = PE::SearchPattern(base, size, PATHHASHSIG, PATHHASHSIG_LEN);

	if (pfnComputePathName)
	{
		InlineHook(pfnComputePathName, &Hasher::ComputePathName);
		g_logger.WriteLine(L"Hook PathNameHash installed");
	}

	*(PVOID*)&pfnComputeFileName = PE::SearchPattern(base, size, NAMEHASHSIG, NAMEHASHSIG_LEN);

	if (pfnComputeFileName)
	{
		InlineHook(pfnComputeFileName, &Hasher::ComputeFileName);
		g_logger.WriteLine(L"Hook FileNameHash installed");
	}
}


#endif


#ifdef DUMP_HXKEY


static bool g_enableDumpHxKey = false;


const tjs_char* TJSStringGetPtr(tTJSString* s);


void PrintIndexKey(PVOID key, PVOID nonce)
{
	wchar_t buf[80];

	PrintHexString(buf, _countof(buf), key, 32);
	g_logger.WriteLine(L"Index Key: %s", buf);

	PrintHexString(buf, _countof(buf), nonce, 16);
	g_logger.WriteLine(L"Index Nonce: %s", buf);
}


// Signature
#define PARSEINDEX_SIG "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x5C\xA1\x2A\x2A\x2A\x2A\x33\xC5\x89\x45\xF0\x53\x56\x57\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x89\x4D\xB8\x8B\x45\x0C\x8B\x75\x08\x89\x45\xBC\xC7\x45"
#define PARSEINDEX_SIG_LEN ( sizeof(PARSEINDEX_SIG) - 1 )
// Prototype
using pfnParseIndex_t = PVOID(_fastcall*)(PVOID, PVOID, PVOID, PVOID);
// Original
pfnParseIndex_t pfnParseIndex;
// Hooked
PVOID _fastcall HookParseIndex(PVOID a1, PVOID a2, PVOID a3, PVOID a4)
{
	auto pathStr = (tTJSString*)a4;
	auto path = TJSStringGetPtr(pathStr);
	auto name = wcsrchr(path, L'/');

	name = name ? name + 1 : path;

	g_logger.WriteLine(L"Parsing archive: %s", name);

	return pfnParseIndex(a1, a2, a3, a4);
}


// Signature
#define DECINDEX_SIG "\xE8\x2A\x2A\x2A\x2A\x83\xC4\x1C\x33\xC0\x8D\xA4\x24\x00\x00\x00\x00\xC6\x44\x05\xCC\x00\x40\x83\xF8\x20"
#define DECINDEX_SIG_LEN ( sizeof(DECINDEX_SIG) - 1 )
// Original
PVOID pfnDecIndex;
// Hooked
_declspec(naked)
void HookDecIndex()
{
	_asm
	{
		pushad
		
		mov eax, [esp+0x2C] // a4 0x20+0xC
		mov edx, [esp+0x30] // a5 0x20+0x10
		push edx
		push eax
		call PrintIndexKey
		add esp, 8

		popad

		jmp pfnDecIndex;
	}
}


// Signature
#define CREATEFILTER_SIG "\x55\x8B\xEC\x83\xEC\x34\xA1\x2A\x2A\x2A\x2A\x33\xC5\x89\x45\xFC\x80\x7D\x10\x00\x53\x56\x8B\x75\x08\x57\x8B\x7D\x0C\x8B\xD9\x75\x06\x33\x73\x08\x33\x7B\x0C\x8B\xC7\xF7\xD0"
#define CREATEFILTER_SIG_LEN ( sizeof(CREATEFILTER_SIG) - 1 )
// Prototype
using pfnCreateFilter_t = PVOID(_fastcall*)(PVOID, PVOID, ULONGLONG, BYTE);
// Original
pfnCreateFilter_t pfnCreateFilter;
// Hooked
PVOID _fastcall HookCreateFilter(PVOID a1, PVOID a2, ULONGLONG a3, BYTE a4)
{
	auto path = Path::GetDirectoryName(g_exePath);

	uint64_t filterKey = *(uint64_t*)((uintptr_t)a1 + 0x8);
	uint32_t splitPosMask = *(uint16_t*)((uintptr_t)a1 + 0x10);
	uint32_t splitPos = *(uint16_t*)((uintptr_t)a1 + 0x14);
	uint32_t randomType = *(uint8_t*)((uintptr_t)a1 + 0x18);

	g_logger.WriteLine(L"Filter Key: 0x%llX", filterKey);
	g_logger.WriteLine(L"Split Pos Mask: 0x%X", splitPosMask);
	g_logger.WriteLine(L"Split Pos: 0x%X", splitPos);
	g_logger.WriteLine(L"Random Type: %d", randomType);

	uint8_t* cxdecTable = (uint8_t*)((uintptr_t)a1 + 0x20);
	uint8_t* cxdecOrder = (uint8_t*)((uintptr_t)a1 + 0x3020);

	File::WriteAllBytes(path + L"\\CxdecTable.bin", cxdecTable, 0x1000);
	File::WriteAllBytes(path + L"\\CxdecOrder.bin", cxdecOrder, 0x11);

	auto isOrderValid = true;

	for (int i = 0; i < 0x11; i++)
	{
		if (i >= 0x00 && i <= 0x07 && cxdecOrder[i] > 7)
		{
			isOrderValid = false;
			break;
		}
		if (i >= 0x08 && i <= 0x0D && cxdecOrder[i] > 5)
		{
			isOrderValid = false;
			break;
		}
		if (i >= 0x0E && i <= 0x10 && cxdecOrder[i] > 2)
		{
			isOrderValid = false;
			break;
		}
	}

	if (isOrderValid)
	{
		constexpr int RO8_TO_GARBRO[] = { 0, 2, 3, 1, 5, 6, 7, 4 };
		constexpr int RO6_TO_GARBRO[] = { 2, 5, 3, 4, 1, 0 };
		constexpr int RO3_TO_GARBRO[] = { 0, 1, 2 };

		int RO8[8]{};
		int RO6[6]{};
		int RO3[3]{};

		for (int i = 0, j = 0x0; i < 8; i++, j++)
			RO8[cxdecOrder[j]] = RO8_TO_GARBRO[i];

		for (int i = 0, j = 0x8; i < 6; i++, j++)
			RO6[cxdecOrder[j]] = RO6_TO_GARBRO[i];

		for (int i = 0, j = 0xE; i < 3; i++, j++)
			RO3[cxdecOrder[j]] = RO3_TO_GARBRO[i];

		g_logger.WriteLine(L"Cxdec Order (8): %d, %d, %d, %d, %d, %d, %d, %d", RO8[0], RO8[1], RO8[2], RO8[3], RO8[4], RO8[5], RO8[6], RO8[7]);
		g_logger.WriteLine(L"Cxdec Order (6): %d, %d, %d, %d, %d, %d", RO6[0], RO6[1], RO6[2], RO6[3], RO6[4], RO6[5]);
		g_logger.WriteLine(L"Cxdec Order (3): %d, %d, %d", RO3[0], RO3[1], RO3[2]);
	}

	PVOID result = pfnCreateFilter(a1, a2, a3, a4);

	UnInlineHook(pfnCreateFilter, HookCreateFilter);

	return result;
}


void HookHxKey(HMODULE hModule)
{
	PVOID base = PE::GetModuleBase(hModule);
	PIMAGE_SECTION_HEADER section = PE::GetSectionHeader(hModule, ".text");

	if (!section)
	{
		g_logger.WriteLine(L"Couldn't to find code section.");
		return;
	}

	PVOID searchBase = (PVOID)((UINT_PTR)base + section->VirtualAddress);
	DWORD searchSize = section->Misc.VirtualSize;

	pfnParseIndex = (pfnParseIndex_t)PE::SearchPattern(searchBase, searchSize, PARSEINDEX_SIG, PARSEINDEX_SIG_LEN);
	if (pfnParseIndex)
	{
		InlineHook(pfnParseIndex, HookParseIndex);
		g_logger.WriteLine(L"Hook PraseIndex installed.");
	}

	pfnDecIndex = PE::SearchPattern(searchBase, searchSize, DECINDEX_SIG, DECINDEX_SIG_LEN);
	if (pfnDecIndex)
	{
		DetourUpdateThread(GetCurrentThread());
		DetourTransactionBegin();
		DetourAttach(&pfnDecIndex, HookDecIndex);
		DetourTransactionCommit();

		g_logger.WriteLine(L"Hook DecIndex installed.");
	}

	pfnCreateFilter = (pfnCreateFilter_t)PE::SearchPattern(searchBase, searchSize, CREATEFILTER_SIG, CREATEFILTER_SIG_LEN);
	if (pfnCreateFilter)
	{
		InlineHook(pfnCreateFilter, HookCreateFilter);
		g_logger.WriteLine(L"Hook CreateFilter installed.");
	}
}


#endif


#ifdef PATCH_SBEAM


static bool g_enableSbeamPatch = false;


void InstallSbeamPatch()
{
	PVOID base = PE::GetModuleBase(g_hEXE);
	DWORD size = PE::GetModuleSize(g_hEXE);

	CHAR patchSig[] = { 0x73, 0x74, 0x65, 0x61, 0x6D, 0x3D, 0x22, 0x79, 0x65, 0x73, 0x22 };

	PVOID patchAddr = PE::SearchPattern(base, size, patchSig, sizeof(patchSig));

	if (patchAddr)
	{
		PE::WriteValue<BYTE>(patchAddr, 0x72);
	}
}


#endif


#ifdef PATCH_SIGNATURECHECK


static bool g_enableSignatureCheckPatch = false;


#define CHECKSIGNATURE_SIG "\x55\x8B\xEC\x8B\x4D\x2A\x85\xC9\x74\x2A\xFF\x75"
#define CHECKSIGNATURE_SIG_LEN ( sizeof(CHECKSIGNATURE_SIG) - 1 )


void PatchSignatureCheck(HMODULE hModule)
{
	PVOID base = PE::GetModuleBase(hModule);
	PIMAGE_SECTION_HEADER section = PE::GetSectionHeader(hModule, ".text");

	if (!section)
	{
		g_logger.WriteLine(L"Couldn't to find code section.");
		return;
	}

	PVOID searchBase = (PVOID)((UINT_PTR)base + section->VirtualAddress);
	DWORD searchSize = section->Misc.VirtualSize;

	PVOID pfnCheckSignature = PE::SearchPattern(searchBase, searchSize, CHECKSIGNATURE_SIG, CHECKSIGNATURE_SIG_LEN);

	if (pfnCheckSignature)
	{
		PVOID patchAddr = (PVOID)((LONG_PTR)pfnCheckSignature + 8);
		BYTE patchData[] = { 0xEB, 0x0F };

		PE::WriteMemory(patchAddr, patchData, sizeof(patchData));
	}
}


#endif


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
		g_tvpStubInitialized = true;

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

#ifdef PATCH_SIGNATURECHECK
					if (g_enableSignatureCheckPatch)
					{
						PatchSignatureCheck(hModule);
					}
#endif

#ifdef DUMP_HASH
					if (g_enableDumpHash)
					{
						HookHash(hModule);
					}
#endif

#ifdef DUMP_HXKEY
					if (g_enableDumpHxKey)
					{
						if (path.find(L"\x6B\x72\x6B\x72\x5F") != std::string::npos)
						{
							HookHxKey(hModule);
						}
					}
#endif
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
	virtual tjs_uint TJS_INTF_METHOD Write(const void* buffer, tjs_uint write_size) = 0;
	virtual void TJS_INTF_METHOD SetEndOfStorage() = 0;
	virtual tjs_uint64 TJS_INTF_METHOD GetSize() = 0;
	virtual ~tTJSBinaryStream() { }
};


#ifdef MEMORYSTREAM


// 
// Version : KRKRZ (MSVC)
// 
#define KRKRZ_OPERATOR_NEW_SIG "\x55\x8B\xEC\xEB\x1F\xFF\x75\x08\xE8\x2A\x2A\x2A\x2A\x59\x85\xC0\x75\x12\x83\x7D\x08\xFF\x75\x07\xE8\x2A\x2A\x2A\x2A\xEB\x05\xE8\x2A\x2A\x2A\x2A\xFF\x75\x08\xE8\x2A\x2A\x2A\x2A\x59\x85\xC0\x74\xD4\x5D\xC3"
#define KRKRZ_OPERATOR_NEW_SIG_LEN ( sizeof(KRKRZ_OPERATOR_NEW_SIG) - 1 )
// Prototype
typedef void* (_cdecl* tKrkrzCdeclNewProc)(size_t);
// Original
tKrkrzCdeclNewProc pfnKrkrzNew = nullptr;


#define KRKRZ_FREE_SIG "\x8B\xFF\x55\x8B\xEC\x83\x7D\x08\x00\x74\x2D\xFF\x75\x08\x6A\x00\xFF\x35\x2A\x2A\x2A\x2A\xFF\x15\x2A\x2A\x2A\x2A\x85\xC0\x75\x18\x56\xE8\x2A\x2A\x2A\x2A\x8B\xF0\xFF\x15\x2A\x2A\x2A\x2A\x50\xE8\x2A\x2A\x2A\x2A\x59\x89\x06\x5E\x5D\xC3"
#define KRKRZ_FREE_SIG_LEN ( sizeof(KRKRZ_FREE_SIG) - 1 )
// Prototype
typedef void(_cdecl* tKrkrzCdeclFreeProc)(void*);
// Original
tKrkrzCdeclFreeProc pfnKrkrzFree = nullptr;


//
// Version : KRKR2 (BCB)
//
#define KRKR2_OPERATOR_NEW_SIG "\x55\x8B\xEC\x83\xC4\xD8\xB8\x2A\x2A\x2A\x2A\x53\x56\x57\x8D\x7D\xFC\x8B\x5D\x08\xE8\x2A\x2A\x2A\x2A\x85\xDB\x75\x53\xBB\x2A\x2A\x2A\x2A\xEB\x4C\x83\x3D\x2A\x2A\x2A\x2A\x2A\x74\x08\xFF\x15\x2A\x2A\x2A\x2A\xEB\x3B\x8D\x45\xD8\xBA\x2A\x2A\x2A\x2A\x50\x6A\x00\x6A\x00\x6A\x00\x6A\x01\x68\x2A\x2A\x2A\x2A\x6A\x00\xB9\x2A\x2A\x2A\x2A\x66\xC7\x45\x2A\x2A\x2A\x89\x17\xFF\x45\xF4\x89\x0F\xFF\x45\xF4\x57\x68\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\x83\xC4\x24\x53\xE8\x2A\x2A\x2A\x2A\x59\x8B\xF0\x85\xC0\x74\xA7\x8B\xC6\x8B\x55\xD8\x64\x89\x15\x2A\x2A\x2A\x2A\x5F\x5E\x5B\x8B\xE5\x5D\xC3"
#define KRKR2_OPERATOR_NEW_SIG_LEN ( sizeof(KRKR2_OPERATOR_NEW_SIG) - 1 )
// Prototype
typedef void* (_cdecl* tKrkr2CdeclNewProc)(size_t);


#define KRKR2_FREE_SIG "\x55\x8B\xEC\x83\xC4\xF4\x53\x8B\x45\x08\x85\xC0\x74\x0F\x8B\xD8\x8D\x45\xF4\xE8\x2A\x2A\x2A\x2A\x8B\xC3\xFF\x55\xF8\x5B\x8B\xE5\x5D\xC3"
#define KRKR2_FREE_SIG_LEN ( sizeof(KRKR2_FREE_SIG) - 1 )
// Prototype
typedef void(_cdecl* tKrkr2CdeclFreeProc)(void*);


static bool g_engineAllocatorInitialized = false;
static bool g_memoryStreamDestructorHooked = false;


void* KrkrNew(size_t count)
{
	return pfnKrkrzNew(count);
}


void KrkrFree(void* ptr)
{
	return pfnKrkrzFree(ptr);
}


//
// Re-implement
//
class CMemoryStream : public tTJSBinaryStream
{
public:
	static void* operator new(size_t count)
	{
		return KrkrNew(count);
	}


	static void operator delete(void* ptr)
	{
		return KrkrFree(ptr);
	}


	CMemoryStream(const uint8_t* data, size_t size)
	{
		if (size > 0)
		{
			m_data.resize(size);
			memcpy(m_data.data(), data, size);
		}
		m_size = size;
		m_offset = 0;
	}


	CMemoryStream(const std::vector<uint8_t>& data)
	{
		m_data = data;
		m_size = m_data.size();
		m_offset = 0;
	}


	CMemoryStream(std::vector<uint8_t>&& data)
	{
		m_data = std::move(data);
		m_size = m_data.size();
		m_offset = 0;
	}


	CMemoryStream(CMemoryStream&& o) noexcept
	{
		m_data = std::move(o.m_data);
		m_size = o.m_size;
		m_offset = o.m_offset;
		o.m_size = 0;
		o.m_offset = 0;
	}


	CMemoryStream(const CMemoryStream&) = delete;
	CMemoryStream& operator=(const CMemoryStream&) = delete;


	~CMemoryStream()
	{
		m_data.clear();
		m_size = 0;
		m_offset = 0;
	}


	tjs_uint64 TJS_INTF_METHOD Seek(tjs_int64 offset, tjs_int whence) override
	{
		switch (whence)
		{
			case TJS_BS_SEEK_SET:
			{
				if (offset >= 0 && offset <= m_size)
					m_offset = (ptrdiff_t)offset;
				break;
			}
			case TJS_BS_SEEK_CUR:
			{
				tjs_int64 new_offset = m_offset + offset;
				if (new_offset >= 0 && new_offset <= m_size)
					m_offset = (ptrdiff_t)new_offset;
				break;
			}
			case TJS_BS_SEEK_END:
			{
				tjs_int64 new_offset = m_size + offset;
				if (new_offset >= 0 && new_offset <= m_size)
					m_offset = (ptrdiff_t)new_offset;
				break;
			}
		}

		return m_offset;
	}


	tjs_uint TJS_INTF_METHOD Read(void* buffer, tjs_uint read_size) override
	{
		tjs_uint count = std::min((size_t)read_size, m_size - m_offset);

		if (count > 0)
		{
			memcpy(buffer, m_data.data() + m_offset, count);
			m_offset += count;
			return count;
		}

		return 0;
	}


	tjs_uint TJS_INTF_METHOD Write(const void* buffer, tjs_uint write_size) override
	{
		UNREFERENCED_PARAMETER(buffer);
		UNREFERENCED_PARAMETER(write_size);
		return 0;
	}


	void TJS_INTF_METHOD SetEndOfStorage() override
	{
		m_offset = m_size;
	}


	tjs_uint64 TJS_INTF_METHOD GetSize() override
	{
		return m_size;
	}


private:
	std::vector<uint8_t> m_data;
	size_t m_size;
	ptrdiff_t m_offset;
};


// Original
PVOID pfnMemoryStreamDestructor = nullptr;
// Hooked
_declspec(naked)
void Krkr2MemoryStreamDestructorDetour()
{
	_asm
	{
		mov ecx, eax
		push edx
		call pfnMemoryStreamDestructor
		ret
	}
}


void HookMemoryStreamDestructorForKrkr2(PVOID pObj)
{
	PDWORD pVftbl = *(PDWORD*)pObj;

	pfnMemoryStreamDestructor = (PVOID)pVftbl[5];

	PVOID pfnDetour = Krkr2MemoryStreamDestructorDetour;
	PE::WriteMemory(&pVftbl[5], &pfnDetour, sizeof(pfnDetour));
}


#endif


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
// Optional Pattern : 55 8B EC 81 C4 ? ? ? ? 53 56 57 89 95 ? ? ? ? 89 85 ? ? ? ? 33 C0 C7 85 ? ? ? ? ? ? ? ? 89 65


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
	g_truncateLog = false;
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

		cJSON* jTruncateLog = cJSON_GetObjectItem(jRoot, "truncateLog");

		if (jTruncateLog)
		{
			g_truncateLog = cJSON_IsTrue(jTruncateLog);
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

#ifdef PATCH_SBEAM
		cJSON* jPatchSbeam = cJSON_GetObjectItem(jRoot, "patchSbeam");

		if (jPatchSbeam)
		{
			g_enableSbeamPatch = cJSON_IsTrue(jPatchSbeam);
		}
#endif

#ifdef PATCH_SIGNATURECHECK
		cJSON* jPatchSignatureCheck = cJSON_GetObjectItem(jRoot, "patchSignatureCheck");

		if (jPatchSignatureCheck)
		{
			g_enableSignatureCheckPatch = cJSON_IsTrue(jPatchSignatureCheck);
		}
#endif

#ifdef DUMP_HASH
		cJSON* jDumpHash = cJSON_GetObjectItem(jRoot, "dumpHash");

		if (jDumpHash)
		{
			g_enableDumpHash = cJSON_IsTrue(jDumpHash);
		}
#endif

#ifdef DUMP_HXKEY
		cJSON* jDumpHxKey = cJSON_GetObjectItem(jRoot, "dumpHxKey");

		if (jDumpHxKey)
		{
			g_enableDumpHxKey = cJSON_IsTrue(jDumpHxKey);
		}
#endif

		cJSON_Delete(jRoot);
	}

	for (auto& s : g_regexRules)
	{
		g_logger.WriteLine(L"Loaded rule \"%s\"", s.c_str());
	}
}


void InstallPatches()
{
#ifdef PATCH_SBEAM
	if (g_enableSbeamPatch)
	{
		InstallSbeamPatch();
	}
#endif
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

#ifdef MEMORYSTREAM
	pfnKrkrzNew = (tKrkrzCdeclNewProc)PE::SearchPattern(base, size, KRKRZ_OPERATOR_NEW_SIG, KRKRZ_OPERATOR_NEW_SIG_LEN);
	pfnKrkrzFree = (tKrkrzCdeclFreeProc)PE::SearchPattern(base, size, KRKRZ_FREE_SIG, KRKRZ_FREE_SIG_LEN);

	if (pfnKrkrzNew && pfnKrkrzFree)
	{
		g_engineAllocatorInitialized = true;
		g_logger.WriteLine(L"KrKrz Allocator Initialized");
	}
	else
	{
		pfnKrkrzNew = (tKrkrzCdeclNewProc)PE::SearchPattern(base, size, KRKR2_OPERATOR_NEW_SIG, KRKR2_OPERATOR_NEW_SIG_LEN);
		pfnKrkrzFree = (tKrkrzCdeclFreeProc)PE::SearchPattern(base, size, KRKR2_FREE_SIG, KRKR2_FREE_SIG_LEN);

		if (pfnKrkrzNew && pfnKrkrzFree)
		{
			g_engineAllocatorInitialized = true;
			g_logger.WriteLine(L"KrKr2 Allocator Initialized");
		}
	}
#endif

#ifdef FIND_EXPORTER
	InlineHook(pfnGetProcAddress, HookGetProcAddress);
#endif
}


void OnStartup()
{
	std::wstring exePath = Util::GetModulePathW(g_hEXE);
	std::wstring dllPath = Util::GetModulePathW(g_hDLL);
	std::wstring cfgPath = Path::ChangeExtension(dllPath, L"json");

	// Build log file path
	auto logPath = Path::GetDirectoryName(dllPath) + L"\\" + Path::GetFileNameWithoutExtension(dllPath) + L"-" + Util::GetTimeString(L"%Y-%m-%d") + L".log";

	Util::WriteDebugMessage(L"[KrkrDump] EXE Path = \"%s\"", exePath.c_str());
	Util::WriteDebugMessage(L"[KrkrDump] DLL Path = \"%s\"", dllPath.c_str());
	Util::WriteDebugMessage(L"[KrkrDump] Log Path = \"%s\"", logPath.c_str());
	Util::WriteDebugMessage(L"[KrkrDump] Cfg Path = \"%s\"", cfgPath.c_str());

	g_exePath = std::move(exePath);
	g_dllPath = std::move(dllPath);

	// Started

	try
	{
		LoadConfiguration();

		Util::WriteDebugMessage(L"Configuration loaded");
	}
	catch (const std::exception&)
	{
		Util::WriteDebugMessage(L"Failed to load configuration");
	}

	if (g_truncateLog)
	{
		File::Delete(logPath);
	}

	g_logger.Open(logPath.c_str());

	g_logger.WriteLine(L"KrkrDump Startup");

	g_logger.WriteLine(L"Game Executable Path = \"%s\"", g_exePath.c_str());

	try
	{
		InstallPatches();
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
