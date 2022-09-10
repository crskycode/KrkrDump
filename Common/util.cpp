// util.cpp

#include <windows.h>
#include <shlobj.h>
#include <ctime>
#include "stringhelper.h"

namespace Util
{
    std::string GetModulePathA(HMODULE hModule)
    {
        DWORD dwBufferSize = MAX_PATH;

        std::string output;

        // Maximum file path limitation
        // @see https://docs.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation
        while (dwBufferSize < USHRT_MAX)
        {
            output.resize(dwBufferSize);

            // Try to get the file name.
            DWORD nSize = GetModuleFileNameA(hModule, const_cast<std::string::pointer>(output.data()), dwBufferSize);
            DWORD dwErrorCode = GetLastError();

            if (dwErrorCode != ERROR_SUCCESS && dwErrorCode != ERROR_INSUFFICIENT_BUFFER)
            {
                // Something unexpected happened.
                return std::string();
            }

            if (dwErrorCode == ERROR_SUCCESS && nSize < dwBufferSize)
            {
                // All characters have been written into the buffer.
                return output.substr(0, nSize);
            }

            if (dwErrorCode == ERROR_INSUFFICIENT_BUFFER || nSize == dwBufferSize)
            {
                // Expand the buffer.
                dwBufferSize *= 2;
            }
        }

        return std::string();
    }

    std::wstring GetModulePathW(HMODULE hModule)
    {
        DWORD dwBufferSize = MAX_PATH;

        std::wstring output;

        // Maximum file path limitation
        // @see https://docs.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation
        while (dwBufferSize < USHRT_MAX)
        {
            output.resize(dwBufferSize);

            // Try to get the file name.
            DWORD nSize = GetModuleFileNameW(hModule, const_cast<std::wstring::pointer>(output.data()), dwBufferSize);
            DWORD dwErrorCode = GetLastError();

            if (dwErrorCode != ERROR_SUCCESS && dwErrorCode != ERROR_INSUFFICIENT_BUFFER)
            {
                // Something unexpected happened.
                return std::wstring();
            }

            if (dwErrorCode == ERROR_SUCCESS && nSize < dwBufferSize)
            {
                // All characters have been written into the buffer.
                return output.substr(0, nSize);
            }

            if (dwErrorCode == ERROR_INSUFFICIENT_BUFFER || nSize == dwBufferSize)
            {
                // Expand the buffer.
                dwBufferSize *= 2;
            }
        }

        return std::wstring();
    }

    std::string GetAppPathA()
    {
        return GetModulePathA(GetModuleHandleW(NULL));
    }

    std::wstring GetAppPathW()
    {
        return GetModulePathW(GetModuleHandleW(NULL));
    }

    std::string GetAppDirectoryA()
    {
        std::string path = GetAppPathA();

        size_t pos = path.find_last_of('\\');

        if (pos != std::string::npos && pos > 0)
        {
            return path.substr(0, pos);
        }

        return path;
    }

	std::wstring GetAppDirectoryW()
	{
		std::wstring path = GetAppPathW();

		size_t pos = path.find_last_of('\\');

		if (pos != std::wstring::npos && pos > 0)
		{
			return path.substr(0, pos);
		}

		return path;
	}

    std::string GetLastErrorMessageA()
    {
        DWORD dwFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM;
        DWORD dwErrorCode = GetLastError();
        DWORD dwLanguageId = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);
        LPSTR pBuffer = NULL;

        if (FormatMessageA(dwFlags, NULL, dwErrorCode, dwLanguageId, (LPSTR)&pBuffer, 0, NULL) == 0)
        {
            return std::string();
        }

        std::string message(pBuffer);

        LocalFree(pBuffer);

        return message;
    }

    std::wstring GetLastErrorMessageW()
    {
        DWORD dwFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM;
        DWORD dwErrorCode = GetLastError();
        DWORD dwLanguageId = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);
        PWSTR pBuffer = NULL;

        if (FormatMessageW(dwFlags, NULL, dwErrorCode, dwLanguageId, (PWSTR)&pBuffer, 0, NULL) == 0)
        {
            return std::wstring();
        }

        std::wstring message(pBuffer);

        LocalFree(pBuffer);

        return message;
    }

    __declspec(noreturn) void ThrowError(const char* format, ...)
    {
        va_list ap;

        va_start(ap, format);
        auto message = StringHelper::VFormat(format, ap);
        va_end(ap);

        MessageBoxA(NULL, message.c_str(), "Fatal Error", MB_ICONERROR | MB_OK);
        ExitProcess(1);
    }

    __declspec(noreturn) void ThrowError(const wchar_t* format, ...)
    {
        va_list ap;

        va_start(ap, format);
        auto message = StringHelper::VFormat(format, ap);
        va_end(ap);

        MessageBoxW(NULL, message.c_str(), L"Fatal Error", MB_ICONERROR | MB_OK);
        ExitProcess(1);
    }

	void WriteDebugMessage(const char* format, ...)
	{
		va_list ap;

		va_start(ap, format);
		auto message = StringHelper::VFormat(format, ap);
		va_end(ap);

		OutputDebugStringA(message.c_str());
	}

	void WriteDebugMessage(const wchar_t* format, ...)
	{
		va_list ap;

		va_start(ap, format);
		auto message = StringHelper::VFormat(format, ap);
		va_end(ap);

		OutputDebugStringW(message.c_str());
	}

    std::string OpenFolderDialog(const std::string& title)
    {
        char buf[MAX_PATH]{};
        BROWSEINFOA bi{};

        bi.hwndOwner = GetActiveWindow();
        bi.pidlRoot = NULL;
        bi.pszDisplayName = buf;
        bi.lpszTitle = title.c_str();
        bi.ulFlags = BIF_NEWDIALOGSTYLE;
        bi.lpfn = NULL;
        bi.lParam = NULL;
        bi.iImage = 0;

        LPITEMIDLIST idl = SHBrowseForFolderA(&bi);

        if (idl == NULL)
        {
            return std::string();
        }

        if (SHGetPathFromIDListA(idl, buf) == FALSE)
        {
            return std::string();
        }

        return std::string(buf);
    }

    std::wstring OpenFolderDialog(const std::wstring& title)
    {
        WCHAR buf[MAX_PATH]{};
        BROWSEINFOW bi{};

        bi.hwndOwner = GetActiveWindow();
        bi.pidlRoot = NULL;
        bi.pszDisplayName = buf;
        bi.lpszTitle = title.c_str();
        bi.ulFlags = BIF_NEWDIALOGSTYLE;
        bi.lpfn = NULL;
        bi.lParam = NULL;
        bi.iImage = 0;

        LPITEMIDLIST idl = SHBrowseForFolderW(&bi);

        if (idl == NULL)
        {
            return std::wstring();
        }

        if (SHGetPathFromIDListW(idl, buf) == FALSE)
        {
            return std::wstring();
        }

        return std::wstring(buf);
    }

    std::string GetTimeString(const char* format)
    {
        time_t tv;
        struct tm tm;
        char buf[32];

        time(&tv);
        localtime_s(&tm, &tv);
        strftime(buf, sizeof(buf), format, &tm);

        return std::string(buf);
    }

    std::wstring GetTimeString(const wchar_t* format)
    {
        time_t tv;
        struct tm tm;
        wchar_t buf[32];

        time(&tv);
        localtime_s(&tm, &tv);
        wcsftime(buf, _countof(buf), format, &tm);

        return std::wstring(buf);
    }
}
