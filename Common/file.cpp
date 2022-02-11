// file.cpp

#include <string>
#include <fstream>
#include <limits>
#include <cstdio>


namespace File
{
	std::string ReadAllText(const std::string& path)
	{
		FILE* fp;
		long long size;
		size_t length;
		unsigned char buf[3];
		bool utf8bom;
		std::string output;

		if (fopen_s(&fp, path.c_str(), "rb") != 0)
		{
			goto error;
		}

		if (_fseeki64(fp, 0, SEEK_END) != 0)
		{
			goto error;
		}

		size = _ftelli64(fp);

		if (size <= 0)
		{
			goto error;
		}

		if (static_cast<uint64_t>(size) > std::numeric_limits<size_t>::max())
		{
			goto error;
		}

		if (_fseeki64(fp, 0, SEEK_SET) != 0)
		{
			goto error;
		}

		length = static_cast<size_t>(size);

		// Check UTF-8 BOM

		utf8bom = false;

		if (fread(buf, 3, 1, fp) == 1)
		{
			if (buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF)
			{
				utf8bom = true;
			}
		}

		if (utf8bom)
		{
			length -= 3;
		}
		else
		{
			if (_fseeki64(fp, 0, SEEK_SET) != 0)
			{
				goto error;
			}
		}

		if (length == 0)
		{
			goto error;
		}

		output.resize(length);

		if (fread(output.data(), length, 1, fp) != 1)
		{
			goto error;
		}

		fclose(fp);

		return output;

	error:
		if (fp)
		{
			fclose(fp);
		}

		return std::string();
	}

	std::string ReadAllText(const std::wstring& path)
	{
		FILE* fp;
		long long size;
		size_t length;
		unsigned char buf[3];
		bool utf8bom;
		std::string output;

		if (_wfopen_s(&fp, path.c_str(), L"rb") != 0)
		{
			goto error;
		}

		if (fp == nullptr)
		{
			goto error;
		}

		if (_fseeki64(fp, 0, SEEK_END) != 0)
		{
			goto error;
		}

		size = _ftelli64(fp);

		if (size <= 0)
		{
			goto error;
		}

		if (static_cast<uint64_t>(size) > std::numeric_limits<size_t>::max())
		{
			goto error;
		}

		if (_fseeki64(fp, 0, SEEK_SET) != 0)
		{
			goto error;
		}

		length = static_cast<size_t>(size);

		// Check UTF-8 BOM

		utf8bom = false;

		if (fread(buf, 3, 1, fp) == 1)
		{
			if (buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF)
			{
				utf8bom = true;
			}
		}

		if (utf8bom)
		{
			length -= 3;
		}
		else
		{
			if (_fseeki64(fp, 0, SEEK_SET) != 0)
			{
				goto error;
			}
		}

		if (length == 0)
		{
			goto error;
		}

		output.resize(length);

		if (fread(output.data(), length, 1, fp) != 1)
		{
			goto error;
		}

		fclose(fp);

		return output;

	error:
		if (fp)
		{
			fclose(fp);
		}

		return std::string();
	}

	bool WriteAllBytes(const std::string& path, const void* buffer, size_t size)
	{
		FILE* fp;

		if (fopen_s(&fp, path.c_str(), "wb") != 0)
		{
			goto error;
		}

		if (buffer == nullptr)
		{
			goto error;
		}

		if (size == 0)
		{
			goto error;
		}

		if (fwrite(buffer, size, 1, fp) != 1)
		{
			goto error;
		}

		fflush(fp);

		fclose(fp);

		return true;

	error:
		if (fp)
		{
			fclose(fp);
		}

		return false;
	}

	bool WriteAllBytes(const std::wstring& path, const void* buffer, size_t size)
	{
		FILE* fp;

		if (_wfopen_s(&fp, path.c_str(), L"wb") != 0)
		{
			goto error;
		}

		if (fp == nullptr)
		{
			goto error;
		}

		if (buffer == nullptr)
		{
			goto error;
		}

		if (size == 0)
		{
			goto error;
		}

		if (fwrite(buffer, size, 1, fp) != 1)
		{
			goto error;
		}

		fflush(fp);

		fclose(fp);

		return true;

	error:
		if (fp)
		{
			fclose(fp);
		}

		return false;
	}

	void Delete(const std::string& path)
	{
		remove(path.c_str());
	}

	void Delete(const std::wstring& path)
	{
		_wremove(path.c_str());
	}
}
