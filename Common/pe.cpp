// pe.cpp

#include "pe.h"

namespace PE
{
	PVOID GetModuleBase(HMODULE hModule)
	{
		MEMORY_BASIC_INFORMATION mem;

		if (!VirtualQuery(hModule, &mem, sizeof(mem)))
			return 0;

		return mem.AllocationBase;
	}

	DWORD GetModuleSize(HMODULE hModule)
	{
		return ((PIMAGE_NT_HEADERS)((ULONG_PTR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew))->OptionalHeader.SizeOfImage;
	}

	PIMAGE_SECTION_HEADER GetSectionHeader(HMODULE hModule, PCSTR lpName)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;

		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return NULL;

		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);

		if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
			return NULL;

		if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0)
			return NULL;

		PIMAGE_SECTION_HEADER pSectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)pNtHeader + sizeof(pNtHeader->Signature) + sizeof(pNtHeader->FileHeader) + pNtHeader->FileHeader.SizeOfOptionalHeader);

		for (DWORD n = 0; n < pNtHeader->FileHeader.NumberOfSections; n++)
		{
			if (strcmp((PCSTR)pSectionHeaders[n].Name, lpName) == 0)
			{
				if (pSectionHeaders[n].VirtualAddress == 0 || pSectionHeaders[n].SizeOfRawData == 0)
					return NULL;

				return &pSectionHeaders[n];
			}
		}

		return NULL;
	}

	static inline PBYTE RvaAdjust(PIMAGE_DOS_HEADER pDosHeader, DWORD raddr)
	{
		if (raddr != NULL)
		{
			return ((PBYTE)pDosHeader) + raddr;
		}

		return NULL;
	}

	PVOID GetImportAddress(HMODULE hModule, LPCSTR lpModuleName, LPCSTR lpProcName)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;

		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return NULL;

		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);

		if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
			return NULL;

		if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0)
			return NULL;

		PIMAGE_IMPORT_DESCRIPTOR iidp = (PIMAGE_IMPORT_DESCRIPTOR)RvaAdjust(pDosHeader, pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		if (iidp == NULL)
			return NULL;

		for (; iidp->OriginalFirstThunk != 0; iidp++)
		{
			LPCSTR lpszModule = (LPCSTR)RvaAdjust(pDosHeader, iidp->Name);

			if (lpszModule == NULL)
				return NULL;

			if (_stricmp(lpszModule, lpModuleName) != 0)
				continue;

			PIMAGE_THUNK_DATA pThunks = (PIMAGE_THUNK_DATA)RvaAdjust(pDosHeader, iidp->OriginalFirstThunk);

			PVOID* pAddrs = (PVOID*)RvaAdjust(pDosHeader, iidp->FirstThunk);

			if (pThunks == NULL)
				continue;

			for (DWORD i = 0; pThunks[i].u1.Ordinal; i++)
			{
				if (IMAGE_SNAP_BY_ORDINAL(pThunks[i].u1.Ordinal))
					continue;

				LPCSTR lpszProc = (PCSTR)RvaAdjust(pDosHeader, (DWORD)pThunks[i].u1.AddressOfData + 2);

				if (lpszProc == NULL)
					continue;

				if (strcmp(lpszProc, lpProcName) == 0)
					return &pAddrs[i];
			}
		}

		return NULL;
	}

	PVOID SearchPattern(PVOID lpStartSearch, DWORD dwSearchLen, const char* lpPattern, DWORD dwPatternLen)
	{
		ULONG_PTR dwStartAddr = (ULONG_PTR)lpStartSearch;
		ULONG_PTR dwEndAddr = dwStartAddr + dwSearchLen - dwPatternLen;

		while (dwStartAddr < dwEndAddr)
		{
			bool found = true;

			for (DWORD i = 0; i < dwPatternLen; i++)
			{
				char code = *(char*)(dwStartAddr + i);

				if (lpPattern[i] != 0x2A && lpPattern[i] != code)
				{
					found = false;
					break;
				}
			}

			if (found)
				return (PVOID)dwStartAddr;

			dwStartAddr++;
		}

		return 0;
	}

	BOOL WriteMemory(PVOID lpAddress, PVOID lpBuffer, DWORD nSize)
	{
		DWORD dwProtect;

		if (VirtualProtect(lpAddress, nSize, PAGE_EXECUTE_READWRITE, &dwProtect))
		{
			memcpy(lpAddress, lpBuffer, nSize);
			VirtualProtect(lpAddress, nSize, dwProtect, &dwProtect);
			return TRUE;
		}

		return FALSE;
	}

	BOOL IATHook(HMODULE hModule, LPCSTR lpModuleName, LPCSTR lpProcName, PVOID lpNewProc, PVOID* lpOriginalProc)
	{
		PVOID lpAddress = GetImportAddress(hModule, lpModuleName, lpProcName);

		if (lpAddress == NULL)
		{
			return FALSE;
		}

		if (lpOriginalProc)
		{
			*lpOriginalProc = *(PVOID*)lpAddress;
		}

		return WriteValue(lpAddress, lpNewProc);
	}
}
