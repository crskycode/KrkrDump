// stringhelper.cpp

#include <algorithm>
#include <string>
#include <cstdarg>

namespace StringHelper
{
	bool StartsWith(const char* source, const char* sub)
	{
		std::string_view vsource(source);
		std::string_view vsub(sub);

		if (vsource.length() == 0 || vsub.length() == 0 || vsource.length() < vsub.length())
		{
			return false;
		}

		return vsource.compare(0, vsub.length(), sub) == 0;
	}

	bool StartsWith(const wchar_t* source, const wchar_t* sub)
	{
		std::wstring_view vsource(source);
		std::wstring_view vsub(sub);

		if (vsource.length() == 0 || vsub.length() == 0 || vsource.length() < vsub.length())
		{
			return false;
		}

		return vsource.compare(0, vsub.length(), sub) == 0;
	}

	bool StartsWith(const std::string& source, const std::string& sub)
	{
		if (source.length() == 0 || sub.length() == 0 || source.length() < sub.length())
		{
			return false;
		}

		return source.compare(0, sub.length(), sub) == 0;
	}

	bool StartsWith(const std::wstring& source, const std::wstring& sub)
	{
		if (source.length() == 0 || sub.length() == 0 || source.length() < sub.length())
		{
			return false;
		}

		return source.compare(0, sub.length(), sub) == 0;
	}

	bool EndsWith(const char* source, const char* sub)
	{
		std::string_view vsource(source);
		std::string_view vsub(sub);

		if (vsource.length() == 0 || vsub.length() == 0 || vsource.length() < vsub.length())
		{
			return false;
		}

		return vsource.compare(vsource.length() - vsub.length(), vsub.length(), sub) == 0;
	}

	bool EndsWith(const wchar_t* source, const wchar_t* sub)
	{
		std::wstring_view vsource(source);
		std::wstring_view vsub(sub);

		if (vsource.length() == 0 || vsub.length() == 0 || vsource.length() < vsub.length())
		{
			return false;
		}

		return vsource.compare(vsource.length() - vsub.length(), vsub.length(), sub) == 0;
	}

	bool EndsWith(const std::string& source, const std::string& sub)
	{
		if (source.length() == 0 || sub.length() == 0 || source.length() < sub.length())
		{
			return false;
		}

		return source.compare(source.length() - sub.length(), sub.length(), sub) == 0;
	}

	bool EndsWith(const std::wstring& source, const std::wstring& sub)
	{
		if (source.length() == 0 || sub.length() == 0 || source.length() < sub.length())
		{
			return false;
		}

		return source.compare(source.length() - sub.length(), sub.length(), sub) == 0;
	}

	std::string ToLower(const std::string& source)
	{
		std::string output = source;

		std::transform(output.begin(), output.end(), output.begin(), [](auto c) { return (std::string::value_type)std::tolower(c); });

		return output;
	}

	std::wstring ToLower(const std::wstring& source)
	{
		std::wstring output = source;

		std::transform(output.begin(), output.end(), output.begin(), [](auto c) { return (std::wstring::value_type)std::tolower(c); });

		return output;
	}

	std::string ToUpper(const std::string& source)
	{
		std::string output = source;

		std::transform(output.begin(), output.end(), output.begin(), [](auto c) { return (std::string::value_type)std::toupper(c); });

		return output;
	}

	std::wstring ToUpper(const std::wstring& source)
	{
		std::wstring output = source;

		std::transform(output.begin(), output.end(), output.begin(), [](auto c) { return (std::wstring::value_type)std::toupper(c); });

		return output;
	}

	std::string Format(const char* format, ...)
	{
		char buf[1024];
		int count;
		va_list ap;

		// Try to print to a small buffer first.
		//   We don't need to allocate a large buffer if it's enough to hold all the characters.
		va_start(ap, format);
		count = vsnprintf(buf, sizeof(buf), format, ap);
		va_end(ap);

		if (count <= 0)
		{
			// Something error happened, We return an empty string.
			return std::string();
		}

		if (count < sizeof(buf))
		{
			// All characters have been written to the small buffer.
			return std::string(buf, count);
		}

		// Allocate a buffer large enough to hold all characters.
		std::string output(count, '\0');

		// Try to print
		va_start(ap, format);
		count = vsnprintf(const_cast<std::string::pointer>(output.data()), output.size() + 1, format, ap);
		va_end(ap);

		if (count <= 0)
		{
			// Something error happened, We return an empty string.
			return std::string();
		}

		return output;
	}

	std::string VFormat(const char* format, va_list ap)
	{
		char buf[1024];
		int count;

		// Try to print to a small buffer first.
		//   We don't need to allocate a large buffer if it's enough to hold all the characters.
		count = vsnprintf(buf, sizeof(buf), format, ap);

		if (count <= 0)
		{
			// Something error happened, We return an empty string.
			return std::string();
		}

		if (count < sizeof(buf))
		{
			// All characters have been written to the small buffer.
			return std::string(buf, count);
		}

		// Allocate a buffer large enough to hold all characters.
		std::string output(count, '\0');

		// Try to print
		count = vsnprintf(const_cast<std::string::pointer>(output.data()), output.size() + 1, format, ap);

		if (count <= 0)
		{
			// Something error happened, We return an empty string.
			return std::string();
		}

		return output;
	}

	std::wstring Format(const wchar_t* format, ...)
	{
		wchar_t buf[1024];
		int count;
		va_list ap;

		// Try to print to a small buffer first.
		//   We don't need to allocate a large buffer if it's enough to hold all the characters.
		va_start(ap, format);
		count = _vsnwprintf_s(buf, _countof(buf), format, ap);
		va_end(ap);

		if (count <= 0)
		{
			// Something error happened, We return an empty string.
			return std::wstring();
		}

		if (count < sizeof(buf))
		{
			// All characters have been written to the small buffer.
			return std::wstring(buf, count);
		}

		// Allocate a buffer large enough to hold all characters.
		std::wstring output(count, '\0');

		// Try to print
		va_start(ap, format);
		count = _vsnwprintf_s(const_cast<std::wstring::pointer>(output.data()), output.size() + 1, output.size() + 1, format, ap);
		va_end(ap);

		if (count <= 0)
		{
			// Something error happened, We return an empty string.
			return std::wstring();
		}

		return output;
	}

	std::wstring VFormat(const wchar_t* format, va_list ap)
	{
		wchar_t buf[1024];
		int count;

		// Try to print to a small buffer first.
		//   We don't need to allocate a large buffer if it's enough to hold all the characters.
		count = _vsnwprintf_s(buf, _countof(buf), format, ap);

		if (count <= 0)
		{
			// Something error happened, We return an empty string.
			return std::wstring();
		}

		if (count < sizeof(buf))
		{
			// All characters have been written to the small buffer.
			return std::wstring(buf, count);
		}

		// Allocate a buffer large enough to hold all characters.
		std::wstring output(count, '\0');

		// Try to print
		count = _vsnwprintf_s(const_cast<std::wstring::pointer>(output.data()), output.size() + 1, output.size() + 1, format, ap);

		if (count <= 0)
		{
			// Something error happened, We return an empty string.
			return std::wstring();
		}

		return output;
	}
}
