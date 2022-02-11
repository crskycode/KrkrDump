// path.cpp

#include <windows.h>
#include <string>

namespace Path
{
	std::string GetFileName(const std::string& path)
	{
		size_t pos;

		pos = path.find_last_of('\\');

		if (pos != std::string::npos)
		{
			return path.substr(pos + 1);
		}

		pos = path.find_last_of('/');

		if (pos != std::string::npos)
		{
			return path.substr(pos + 1);
		}

		return path;
	}

	std::wstring GetFileName(const std::wstring& path)
	{
		size_t pos;

		pos = path.find_last_of(L'\\');

		if (pos != std::wstring::npos)
		{
			return path.substr(pos + 1);
		}

		pos = path.find_last_of(L'/');

		if (pos != std::wstring::npos)
		{
			return path.substr(pos + 1);
		}

		return path;
	}

	std::string GetFileNameWithoutExtension(const std::string& path)
	{
		std::string name = GetFileName(path);

		size_t pos = name.find_last_of('.');

		if (pos != std::string::npos && pos > 0)
		{
			return name.substr(0, pos);
		}

		return name;
	}

	std::wstring GetFileNameWithoutExtension(const std::wstring& path)
	{
		std::wstring name = GetFileName(path);

		size_t pos = name.find_last_of(L'.');

		if (pos != std::wstring::npos && pos > 0)
		{
			return name.substr(0, pos);
		}

		return name;
	}

	std::string GetDirectoryName(const std::string& path)
	{
		size_t pos;

		pos = path.find_last_of('\\');

		if (pos != std::string::npos && pos > 0)
		{
			return path.substr(0, pos);
		}

		pos = path.find_last_of('/');

		if (pos != std::string::npos && pos > 0)
		{
			return path.substr(0, pos);
		}

		return std::string();
	}

	std::wstring GetDirectoryName(const std::wstring& path)
	{
		size_t pos;

		pos = path.find_last_of(L'\\');

		if (pos != std::wstring::npos && pos > 0)
		{
			return path.substr(0, pos);
		}

		pos = path.find_last_of(L'/');

		if (pos != std::wstring::npos && pos > 0)
		{
			return path.substr(0, pos);
		}

		return std::wstring();
	}

	std::string GetExtension(const std::string& path)
	{
		int length = static_cast<int>(path.length());

		for (int i = length - 1; i >= 0; i--)
		{
			char ch = path[i];

			if (ch == '.')
			{
				if (i != length - 1)
				{
					return path.substr(i, length - i);
				}
				else
				{
					return std::string();
				}
			}

			if (ch == '\\' || ch == '/')
			{
				break;
			}
		}

		return std::string();
	}

	std::wstring GetExtension(const std::wstring& path)
	{
		int length = static_cast<int>(path.length());

		for (int i = length - 1; i >= 0; i--)
		{
			wchar_t ch = path[i];

			if (ch == '.')
			{
				if (i != length - 1)
				{
					return path.substr(i, length - i);
				}
				else
				{
					return std::wstring();
				}
			}

			if (ch == L'\\' || ch == L'/')
			{
				break;
			}
		}

		return std::wstring();
	}

	std::string ChangeExtension(const std::string& path, const std::string& ext)
	{
		int length = static_cast<int>(path.length());

		if (length == 0)
		{
			return std::string();
		}

		int subLength = static_cast<int>(path.length());

		for (int i = length - 1; i >= 0; i--)
		{
			char ch = path[i];

			if (ch == '.')
			{
				subLength = i;
				break;
			}

			if (ch == '\\' || ch == '/')
			{
				break;
			}
		}

		std::string subPath = path.substr(0, subLength);

		if (ext.length() == 0)
		{
			return subPath;
		}

		if (ext.front() != '.')
		{
			return subPath + "." + ext;
		}
		else
		{
			return subPath + ext;
		}
	}

	std::wstring ChangeExtension(const std::wstring& path, const std::wstring& ext)
	{
		int length = static_cast<int>(path.length());

		if (length == 0)
		{
			return std::wstring();
		}

		int subLength = static_cast<int>(path.length());

		for (int i = length - 1; i >= 0; i--)
		{
			wchar_t ch = path[i];

			if (ch == L'.')
			{
				subLength = i;
				break;
			}

			if (ch == L'\\' || ch == L'/')
			{
				break;
			}
		}

		std::wstring subPath = path.substr(0, subLength);

		if (ext.length() == 0)
		{
			return subPath;
		}

		if (ext.front() != L'.')
		{
			return subPath + L'.' + ext;
		}
		else
		{
			return subPath + ext;
		}
	}

	std::string GetFullPath(const std::string& path)
	{
		DWORD dwBufferSize = MAX_PATH;

		std::string output;

		while (dwBufferSize < USHRT_MAX)
		{
			output.resize(dwBufferSize);

			DWORD nSize = GetFullPathNameA(path.c_str(), dwBufferSize, const_cast<std::string::pointer>(output.data()), NULL);

			if (nSize == 0)
			{
				return std::string();
			}

			if (nSize < dwBufferSize)
			{
				return output.substr(0, nSize);
			}
			else
			{
				dwBufferSize *= 2;
			}
		}

		return std::string();
	}

	std::wstring GetFullPath(const std::wstring& path)
	{
		DWORD dwBufferSize = MAX_PATH;

		std::wstring output;

		while (dwBufferSize < USHRT_MAX)
		{
			output.resize(dwBufferSize);

			DWORD nSize = GetFullPathNameW(path.c_str(), dwBufferSize, const_cast<std::wstring::pointer>(output.data()), NULL);

			if (nSize == 0)
			{
				return std::wstring();
			}

			if (nSize < dwBufferSize)
			{
				return output.substr(0, nSize);
			}
			else
			{
				dwBufferSize *= 2;
			}
		}

		return std::wstring();
	}
}
