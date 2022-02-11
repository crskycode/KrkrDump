// path.h

#pragma once

#include <string>

namespace Path
{
	std::string GetFileName(const std::string& path);
	std::wstring GetFileName(const std::wstring& path);
	std::string GetFileNameWithoutExtension(const std::string& path);
	std::wstring GetFileNameWithoutExtension(const std::wstring& path);
	std::string GetDirectoryName(const std::string& path);
	std::wstring GetDirectoryName(const std::wstring& path);
	std::string GetExtension(const std::string& path);
	std::wstring GetExtension(const std::wstring& path);
	std::string ChangeExtension(const std::string& path, const std::string& ext);
	std::wstring ChangeExtension(const std::wstring& path, const std::wstring& ext);
	std::string GetFullPath(const std::string& path);
	std::wstring GetFullPath(const std::wstring& path);
}
