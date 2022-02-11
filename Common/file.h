// file.h

#pragma once

#include <string>

namespace File
{
	std::string ReadAllText(const std::string& path);
	std::string ReadAllText(const std::wstring& path);
	bool WriteAllBytes(const std::string& path, const void* buffer, size_t size);
	bool WriteAllBytes(const std::wstring& path, const void* buffer, size_t size);
	void Delete(const std::string& path);
	void Delete(const std::wstring& path);
}
