// util.h

#pragma once

#include <windows.h>
#include <string>

namespace Util
{
	// Get the full path of the specified module.
	std::string GetModulePathA(HMODULE hModule);

	// Get the full path of the specified module.
	std::wstring GetModulePathW(HMODULE hModule);

	// Get the full path to the executable.
	std::string GetAppPathA();

	// Get the full path to the executable.
	std::wstring GetAppPathW();

	// Get the directory path to the executable.
	std::string GetAppDirectoryA();

	// Get the directory path to the executable.
	std::wstring GetAppDirectoryW();

	// Get message from Win32 last error code.
	std::string GetLastErrorMessageA();

	// Get message from Win32 last error code.
	std::wstring GetLastErrorMessageW();

	// Display an error message then close the application.
	__declspec(noreturn) void ThrowError(const char* format, ...);

	// Display an error message then close the application.
	__declspec(noreturn) void ThrowError(const wchar_t* format, ...);

	// Sends a string to the debugger for display.
	void WriteDebugMessage(const char* format, ...);

	// Sends a string to the debugger for display.
	void WriteDebugMessage(const wchar_t* format, ...);

	// Display a folder select dialog.
	std::string OpenFolderDialog(const std::string& title);

	// Display a folder select dialog.
	std::wstring OpenFolderDialog(const std::wstring& title);

	// Get a formatted time string.
	std::string GetTimeString(const char* format);

	// Get a formatted time string.
	std::wstring GetTimeString(const wchar_t* format);
}
