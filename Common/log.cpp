// log.cpp

#include <cstdarg>
#include <ctime>
#include "log.h"
#include "stringhelper.h"
#include "encoding.h"


namespace Log
{
	Logger::Logger() : m_pOutput{}
	{
	}

	Logger::Logger(const wchar_t* lpFileName)
		: m_pOutput{}
	{
		Open(lpFileName);
	}

	Logger::~Logger()
	{
		Close();
	}

	void Logger::Open(const wchar_t* lpFileName)
	{
		m_pOutput = _wfsopen(lpFileName, L"at", _SH_DENYWR);
	}

	void Logger::Close()
	{
		Flush();

		if (m_pOutput)
		{
			fclose(m_pOutput);
			m_pOutput = nullptr;
		}
	}

	void Logger::Flush()
	{
		if (m_pOutput)
		{
			fflush(m_pOutput);
		}
	}

	static std::string GetTimeString()
	{
		time_t tv;
		struct tm tm;
		char buf[32];

		time(&tv);
		localtime_s(&tm, &tv);
		strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);

		return std::string(buf);
	}

	void Logger::WriteAnsi(int iCodePage, const char* lpFormat, ...)
	{
		if (!m_pOutput)
		{
			return;
		}

		va_list ap;

		va_start(ap, lpFormat);
		auto content = StringHelper::VFormat(lpFormat, ap);
		va_end(ap);

		auto unicode = Encoding::AnsiToUnicode(content, iCodePage);
		auto output = Encoding::UnicodeToAnsi(unicode, Encoding::CodePage::UTF_8);

		fwrite(output.data(), output.length(), 1, m_pOutput);
		fflush(m_pOutput);
	}

	void Logger::WriteLineAnsi(int iCodePage, const char* lpFormat, ...)
	{
		if (!m_pOutput)
		{
			return;
		}

		va_list ap;

		va_start(ap, lpFormat);
		auto content = StringHelper::VFormat(lpFormat, ap);
		va_end(ap);

		auto unicode = Encoding::AnsiToUnicode(content, iCodePage);
		auto utf = Encoding::UnicodeToAnsi(unicode, Encoding::CodePage::UTF_8);
		auto timestamp = GetTimeString();

		auto output = timestamp + " | " + utf + "\n";

		fwrite(output.data(), output.length(), 1, m_pOutput);
		fflush(m_pOutput);
	}

	void Logger::Write(const wchar_t* lpFormat, ...)
	{
		if (!m_pOutput)
		{
			return;
		}

		va_list ap;

		va_start(ap, lpFormat);
		auto content = StringHelper::VFormat(lpFormat, ap);
		va_end(ap);

		auto output = Encoding::UnicodeToAnsi(content, Encoding::CodePage::UTF_8);

		fwrite(output.data(), output.length(), 1, m_pOutput);
		fflush(m_pOutput);
	}

	void Logger::WriteLine(const wchar_t* lpFormat, ...)
	{
		if (!m_pOutput)
		{
			return;
		}

		va_list ap;

		va_start(ap, lpFormat);
		auto content = StringHelper::VFormat(lpFormat, ap);
		va_end(ap);

		auto utf = Encoding::UnicodeToAnsi(content, Encoding::CodePage::UTF_8);
		auto timestamp = GetTimeString();

		auto output = timestamp + " | " + utf + "\n";

		fwrite(output.data(), output.length(), 1, m_pOutput);
		fflush(m_pOutput);
	}
}
