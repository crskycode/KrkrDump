// pe.h

#pragma once

#include <windows.h>
#include <type_traits>

namespace PE
{
	// Get the base address of the specified module.
	PVOID GetModuleBase(HMODULE hModule);

	// Get the size of the specified module.
	DWORD GetModuleSize(HMODULE hModule);

	// Get the section with the specified name.
	PIMAGE_SECTION_HEADER GetSectionHeader(HMODULE hModule, PCSTR lpName);

	// Get the address of the imported function in the import table.
	PVOID GetImportAddress(HMODULE hModule, LPCSTR lpModuleName, LPCSTR lpProcName);

	// Searche memory for the specified pattern.
	PVOID SearchPattern(PVOID lpStartSearch, DWORD dwSearchLen, const char* lpPattern, DWORD dwPatternLen);

	// Write data to the specified address.
	BOOL WriteMemory(PVOID lpAddress, PVOID lpBuffer, DWORD nSize);

	// Writes a scalar value to the specified address.
	//  If you pass a pointer, the value of that pointer is written.
	template<typename T, typename std::enable_if_t<std::is_scalar_v<T>, bool> = true>
	BOOL WriteValue(PVOID lpAddress, T tValue)
	{
		return WriteMemory(lpAddress, &tValue, sizeof(T));
	}

	// Replace imported function in the import table.
	BOOL IATHook(HMODULE hModule, LPCSTR lpModuleName, LPCSTR lpProcName, PVOID lpNewProc, PVOID* lpOriginalProc);
}
