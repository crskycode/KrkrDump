// stringhelper.h

#pragma once

#include <string>

namespace StringHelper
{
	bool StartsWith(const char* source, const char* sub);
	bool StartsWith(const wchar_t* source, const wchar_t* sub);
	bool StartsWith(const std::string& source, const std::string& sub);
	bool StartsWith(const std::wstring& source, const std::wstring& sub);
	bool EndsWith(const char* source, const char* sub);
	bool EndsWith(const wchar_t* source, const wchar_t* sub);
	bool EndsWith(const std::string& source, const std::string& sub);
	bool EndsWith(const std::wstring& source, const std::wstring& sub);

	std::string ToLower(const std::string& source);
	std::wstring ToLower(const std::wstring& source);
	std::string ToUpper(const std::string& source);
	std::wstring ToUpper(const std::wstring& source);

	std::string Format(const char* format, ...);
	std::string VFormat(const char* format, va_list ap);
	std::wstring Format(const wchar_t* format, ...);
	std::wstring VFormat(const wchar_t* format, va_list ap);
}
