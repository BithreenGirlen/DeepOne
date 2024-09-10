/*ファイル操作・文字列操作・コンソール出力*/

#include <Windows.h>
#include <urlmon.h>
#include <atlbase.h>

#include <string>

#include "file_utility.h"

#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "shlwapi.lib")


struct ComInit
{
	HRESULT m_hrComInit;
	ComInit() : m_hrComInit(::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)) {}
	~ComInit() { if (SUCCEEDED(m_hrComInit)) ::CoUninitialize(); }
};

/*-----------------------  内部関数  -----------------------*/

void WriteMessage(const char* msg);

bool WriteStringToFile(std::string data, const char* file_path);

bool GetInternetResourceSize(const char* url, ULARGE_INTEGER& size);
std::string GetFileNameFromUrl(std::string url);
std::string GetDirectoryFromUrl(std::string url);


/*伝文出力*/
void WriteMessage(const char* msg)
{
	char stamp[16];
	SYSTEMTIME tm;
	::GetLocalTime(&tm);
	sprintf_s(stamp, "%02d:%02d:%02d:%03d ", tm.wHour, tm.wMinute, tm.wSecond, tm.wMilliseconds);
	std::string str = stamp + std::string(msg) + "\r\n";
	printf(str.c_str());
}

/*実行プロセスの階層取得*/
std::string GetFolderBasePath()
{
	char application_path[MAX_PATH]{};
	::GetModuleFileNameA(nullptr, application_path, MAX_PATH);
	std::string::size_type pos = std::string(application_path).find_last_of("\\/");
	return std::string(application_path).substr(0, pos) + "\\/";
}
/*作業フォルダ作成*/
std::string CreateWorkFolder(const char* folder_name)
{
	std::string strFolder = folder_name != nullptr ? GetFolderBasePath() + folder_name + "\\/" : GetFolderBasePath();
	::CreateDirectoryA(strFolder.c_str(), nullptr);
	return strFolder;
}
/*入れ子作業フォルダ作成*/
std::string CreateNestedWorkFolder(const std::string& strRelativePath)
{
	if (!strRelativePath.empty())
	{
		std::string strFolder = GetFolderBasePath();
		size_t nRead = 0;
		for (;;)
		{
			size_t nPos = strRelativePath.substr(nRead).find_first_of("\\/");
			if (nPos == std::string::npos)
			{
				strFolder += strRelativePath.substr(nRead) +"\\/";
				::CreateDirectoryA(strFolder.c_str(), nullptr);
				break;
			}

			strFolder += strRelativePath.substr(nRead, nPos) + "\\/";
			::CreateDirectoryA(strFolder.c_str(), nullptr);
			nRead += nPos + 1;
		}

		return strFolder;
	}

	return std::string();
}
/*相対URLを元にフォルダ作成*/
std::string CreateFolderBasedOnRelativeUrl(const std::string& strUrl, const std::string& strBaseFolder, int iDepth, bool bBeFilePath)
{
	if (!strUrl.empty())
	{
		std::string strFolder = strBaseFolder;
		size_t nRead = 0;
		int iOccurrence = 0;
		for (;;)
		{
			size_t nPos = strUrl.substr(nRead).find_first_of("/");
			if (nPos == std::string::npos)
			{
				if (bBeFilePath)
				{
					strFolder += strUrl.substr(nRead);
				}
				break;
			}
			++iOccurrence;
			if (iOccurrence > iDepth && nPos != 0)
			{
				strFolder += strUrl.substr(nRead, nPos) + "\\/";
				::CreateDirectoryA(strFolder.c_str(), nullptr);
			}
			nRead += nPos + 1;
		}

		return strFolder;
	}

	return std::string();
}

/*ファイルのメモリ展開*/
char* LoadExistingFile(const char* file_path)
{
	HANDLE hFile = ::CreateFileA(file_path, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD dwSize = ::GetFileSize(hFile, nullptr);
		if (dwSize != INVALID_FILE_SIZE)
		{
			char* buffer = static_cast<char*>(malloc(static_cast<size_t>(dwSize + 1ULL)));
			if (buffer != nullptr)
			{
				DWORD dwRead = 0;
				BOOL iRet = ::ReadFile(hFile, buffer, dwSize, &dwRead, nullptr);
				if (iRet)
				{
					::CloseHandle(hFile);
					*(buffer + dwRead) = '\0';
					return buffer;
				}
				else
				{
					free(buffer);
				}
			}
		}
		::CloseHandle(hFile);
	}

	return nullptr;
}
/*メモリのファイル出力*/
bool WriteStringToFile(std::string data, const char* file_path)
{
	BOOL iRet = 0;

	if (file_path != nullptr)
	{
		HANDLE hFile = ::CreateFileA(file_path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			::SetFilePointer(hFile, NULL, nullptr, FILE_END);

			DWORD bytesWrite = 0;
			iRet = ::WriteFile(hFile, data.data(), static_cast<DWORD>(data.size()), &bytesWrite, nullptr);
			::CloseHandle(hFile);
		}
	}
	return iRet > 0;
}
/*保存処理メッセージ出力*/
void SaveStringToFile(std::string data, const char* file_path)
{
	if (file_path != nullptr)
	{
		std::string strFileName = GetFileNameFromUrl(file_path);
		if (!strFileName.empty())
		{
			bool bRet = WriteStringToFile(data, file_path);
			if (bRet)
			{
				WriteMessage(std::string(strFileName).append(" success.").c_str());
			}
			else
			{
				WriteMessage(std::string(strFileName).append(" failed.").c_str());
			}
		}
	}

}
/*ファイル有無確認*/
bool DoesFilePathExist(const char* file_path)
{
	BOOL iRet = ::PathFileExistsA(file_path);
	if (iRet)
	{
		std::string strFileName = GetFileNameFromUrl(file_path);
		WriteMessage(std::string(strFileName).append(" already exists.").c_str());
	}

	return iRet == TRUE;
}

/*電子網資源の大きさ取得*/
bool GetInternetResourceSize(const char* url, ULARGE_INTEGER& size)
{
	ComInit init;
	CComPtr<IStream> pStream;
	HRESULT hr = ::URLOpenBlockingStreamA(nullptr, url, &pStream, 0, nullptr);

	if (hr == S_OK)
	{
		STATSTG stat;
		hr = pStream->Stat(&stat, STATFLAG_DEFAULT);
		if (hr == S_OK)
		{
			size = stat.cbSize;
			return true;
		}
	}
	return false;
}
/*URLからファイル名取得*/
std::string GetFileNameFromUrl(std::string url)
{
	size_t pos = url.find_last_of("/");
	if (pos != std::string::npos)
	{
		return url.substr(pos + 1);
	}

	return std::string();
}
/*URLから階層取得*/
std::string GetDirectoryFromUrl(std::string url)
{
	size_t pos = url.find_last_of("/");
	if (pos != std::string::npos)
	{
		return url.substr(0, pos + 1);
	}

	return std::string();
}
/*電子網資源の保存*/
bool SaveInternetResourceToFile(const char* url, const char* folder, const char* file_name, unsigned long nMinFileSize, bool bFolderCreation)
{
	std::string strFileName = file_name == nullptr ? GetFileNameFromUrl(url) : strchr(file_name, '/') == nullptr ? file_name : GetFileNameFromUrl(file_name);
	if (!strFileName.empty())
	{
		std::string strFilePath = folder + strFileName;

		if (!::PathFileExistsA(strFilePath.c_str()))
		{
			ULARGE_INTEGER size{};
			bool bRet = GetInternetResourceSize(url, size);
			if (bRet)
			{
				if (size.LowPart > nMinFileSize)
				{
					if (bFolderCreation)
					{
						::CreateDirectoryA(folder, nullptr);
					}

					HRESULT hr = ::URLDownloadToFileA(nullptr, url, strFilePath.c_str(), 0, nullptr);
					if (hr == S_OK)
					{
						WriteMessage(std::string(url).append(" success").c_str());
						return true;
					}
					else
					{
						WriteMessage(std::string(url).append(" failed").c_str());
					}
				}

			}
		}
		else
		{
			WriteMessage(std::string(strFileName).append(" already exists.").c_str());
			return true;
		}
	}
	else
	{
		WriteMessage("File path invalid.");
	}

	return false;
}
/*電子網資源のメモリ展開*/
bool LoadInternetResourceToBuffer(const char* url, char** dst, unsigned long* ulSize)
{
	if (url == nullptr || *dst != nullptr)return false;

	ComInit init;
	CComPtr<IStream> pStream;
	HRESULT hr = ::URLOpenBlockingStreamA(nullptr, url, &pStream, 0, nullptr);

	if (hr == S_OK)
	{
		STATSTG stat;
		hr = pStream->Stat(&stat, STATFLAG_DEFAULT);
		if (hr == S_OK)
		{
			char* buffer = static_cast<char*>(malloc(stat.cbSize.LowPart + 1LL));
			if (buffer != nullptr)
			{
				DWORD dwReadBytes = 0;
				DWORD dwSize = 0;
				for (;;)
				{
					hr = pStream->Read(buffer + dwSize, stat.cbSize.LowPart - dwSize, &dwReadBytes);
					if (FAILED(hr))break;
					dwSize += dwReadBytes;
					if (dwSize >= stat.cbSize.LowPart)break;
				}
				*(buffer + dwSize) = '\0';
				*ulSize = dwSize;
				*dst = buffer;

				return true;
			}
		}
	}

	return false;
}

/*JSON特性体の抽出*/
bool ExtractJsonObject(char** src, const char* name, char** dst)
{
	char* p = nullptr;
	char* pp = *src;
	char* q = nullptr;
	char* qq = nullptr;
	size_t nLen = 0;
	int iCount = 0;

	if (name != nullptr)
	{
		p = strstr(pp, name);
		if (p == nullptr)return false;

		pp = strchr(p, ':');
		if (pp == nullptr)return false;
	}
	else
	{
		p = strchr(pp, '{');
		if (p == nullptr)return false;
		++iCount;
		pp = p + 1;
	}

	for (;;)
	{
		q = strchr(pp, '}');
		if (q == nullptr)return false;

		qq = strchr(pp, '{');
		if (qq == nullptr)break;

		if (q < qq)
		{
			--iCount;
			pp = q + 1;
		}
		else
		{
			++iCount;
			pp = qq + 1;
		}

		if (iCount == 0)break;
	}

	for (; iCount > 0; ++q)
	{
		if (*q == '}')
		{
			--iCount;
		}
	}
	++q;

	nLen = q - p;
	char* pBuffer = static_cast<char*>(malloc(nLen + 1));
	if (pBuffer == nullptr)return false;

	memcpy(pBuffer, p, nLen);
	*(pBuffer + nLen) = '\0';
	*dst = pBuffer;
	*src = q;

	return true;
}
/*JSON配列の抽出*/
bool ExtractJsonArray(char** src, const char* name, char** dst)
{
	char* p = nullptr;
	char* pp = *src;
	char* q = nullptr;
	char* qq = nullptr;
	size_t nLen = 0;
	int iCount = 0;

	if (name != nullptr)
	{
		p = strstr(pp, name);
		if (p == nullptr)return false;

		pp = strchr(p, ':');
		if (pp == nullptr)return false;
	}
	else
	{
		p = strchr(pp, '[');
		if (p == nullptr)return false;
		++iCount;
		pp = p + 1;
	}

	for (;;)
	{
		q = strchr(pp, ']');
		if (q == nullptr)return false;

		qq = strchr(pp, '[');
		if (qq == nullptr)break;

		if (q < qq)
		{
			--iCount;
			pp = q + 1;
		}
		else
		{
			++iCount;
			pp = qq + 1;
		}

		if (iCount == 0)break;
	}

	for (; iCount > 0; ++q)
	{
		if (*q == ']')
		{
			--iCount;
		}
	}
	++q;

	nLen = q - p;
	char* pBuffer = static_cast<char*>(malloc(nLen + 1));
	if (pBuffer == nullptr)return false;

	memcpy(pBuffer, p, nLen);
	*(pBuffer + nLen) = '\0';
	*dst = pBuffer;
	*src = q;

	return true;
}
/*JSON区切り位置探索*/
char* FindJsonValueEnd(char* src)
{
	const char ref[] = ",}\"]";
	return strpbrk(src, ref);
}
/*JSON要素の値を取得*/
bool GetJsonElementValue(char* src, const char* name, char* dst, size_t nDstSize)
{
	char* p = nullptr;
	char* pp = src;
	size_t nLen = 0;

	p = strstr(pp, name);
	if (p == nullptr)return false;

	pp = strchr(p, ':');
	if (pp == nullptr)return false;
	++pp;

	p = FindJsonValueEnd(pp);
	if (p == nullptr)return false;
	if (*p == '"')
	{
		pp = p + 1;
		p = strchr(pp, '"');
		if (p == nullptr)return false;
	}

	nLen = p - pp;
	if (nLen > nDstSize - 1)return false;
	memcpy(dst, pp, nLen);
	*(dst + nLen) = '\0';

	return true;
}
/*JSON変数名開始位置探索*/
char* FindJsonNameStart(char* src)
{
	const char ref[] = " :{[,";
	for (char* p = src; p != nullptr; ++p)
	{
		bool b = false;
		/*終端除外*/
		for (size_t i = 0; i < sizeof(ref) - 1; ++i)
		{
			if (*p == ref[i])
			{
				b = true;
			}
		}
		if (!b)return p;
	}

	return nullptr;
}
/*名称終わり位置まで読み進め*/
bool ReadUpToJsonNameEnd(char** src, const char* name, char* value, size_t nValueSize)
{
	char* p = nullptr;
	char* pp = *src;

	if (name != nullptr)
	{
		p = strstr(pp, name);
		if (p == nullptr)return false;
	}
	else
	{
		p = FindJsonNameStart(pp);
		if (p == nullptr)return false;
		++p;
	}

	pp = FindJsonValueEnd(p);
	if (pp == nullptr)return false;

	/*名称取得*/
	if (name == nullptr && value != nullptr && nValueSize != 0)
	{
		size_t nLen = pp - p;
		if (nLen > nValueSize - 1)return false;
		memcpy(value, p, nLen);
		*(value + nLen) = '\0';
	}

	*src = *pp == '"' ? pp + 1 : pp;

	return true;
}

std::wstring WidenUtf8(std::string str)
{
	if (!str.empty())
	{
		int len = ::MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.length()), nullptr, 0);
		if (len > 0)
		{
			std::wstring wstr(len, 0);
			::MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.length()), &wstr[0], len);
			return wstr;
		}
	}

	return std::wstring();
}

std::string NarrowUtf8(std::wstring wstr)
{
	if (!wstr.empty())
	{
		int len = ::WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.length()), nullptr, 0, nullptr, nullptr);
		if (len > 0)
		{
			std::string str(len, 0);
			::WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.length()), &str[0], len, nullptr, nullptr);
			return str;
		}
	}
	return std::string();
}

/*文字置換*/
char* ReplaceString(char* src, const char* pzOld, const char* pzNew)
{
	if (src == nullptr)return nullptr;
	size_t nSrcLen = strlen(src);

	size_t nOldLen = strlen(pzOld);
	if (nOldLen == 0)return nullptr;

	size_t nNewLen = strlen(pzNew);

	char* p = nullptr;
	char* pp = src;
	int iCount = 0;

	for (;;)
	{
		p = strstr(pp, pzOld);
		if (p == nullptr)break;

		pp = p + nOldLen;
		++iCount;
	}

	size_t nSize = nSrcLen + iCount * (nNewLen - nOldLen) + 1;
	char* pResult = static_cast<char*>(malloc(nSize));
	if (pResult == nullptr)return nullptr;

	size_t pos = 0;
	size_t len = 0;
	pp = src;
	for (;;)
	{
		p = strstr(pp, pzOld);
		if (p == nullptr)
		{
			len = nSrcLen - (pp - src);
			memcpy(pResult + pos, pp, len);
			pos += len;
			break;
		}

		len = p - pp;
		memcpy(pResult + pos, pp, len);
		pos += len;
		memcpy(pResult + pos, pzNew, nNewLen);
		pos += nNewLen;
		pp = p + nOldLen;
	}

	*(pResult + pos) = '\0';
	return pResult;
}

/*経路からファイル名取得*/
std::string GetFileNameFromFilePath(const char* path)
{
	if (path != nullptr)
	{
		std::string strPath = path;
		size_t pos = strPath.find_last_of("\\/");
		if (pos != std::string::npos)
		{
			return strPath.substr(pos + 1);
		}
	}
	return std::string();
}
/*ファイル名から拡張子取得*/
std::string GetExtensionFromFileName(const char* file_name)
{
	if (file_name != nullptr)
	{
		std::string strFile = file_name;
		size_t nPos = strFile.rfind('/');
		nPos = nPos != std::string::npos ? nPos + 1 : 0;
		nPos = strFile.find('.', nPos);
		if (nPos != std::string::npos)
		{
			return strFile.substr(nPos);
		}
	}
	return std::string();
}
/*ファイル名無効文字の削除*/
std::string TruncateFileName(const char* file_name)
{
	if (file_name != nullptr)
	{
		std::string str = GetFileNameFromUrl(std::string(file_name));
		return str.empty() ? std::string(file_name) : str;
	}
	return std::string();
}
/*拡張子除外*/
std::string RemoveFileExtension(const char* file_name)
{
	if (file_name != nullptr)
	{
		std::string strFile = file_name;
		size_t pos = strFile.find_last_of(".");
		if (pos != std::string::npos)
		{
			return strFile.substr(0, pos);
		}
	}
	return std::string();
}

char* EncodeUri(const char* src)
{
	if (src == nullptr)return nullptr;

	const char HexDigits[] = "0123456789ABCDEF";

	size_t nSrcLen = strlen(src);
	char* pResult = static_cast<char*>(malloc(nSrcLen * 3 + 1LL));
	if (pResult == nullptr)return nullptr;

	char* pPos = pResult;
	size_t nDstLen = 0;

	for (size_t i = 0; i < nSrcLen; ++i)
	{
		char p = *(src + i);

		/*RFC 3986 Unreserved Characters*/
		if ((p >= 'A' && p <= 'Z') || (p >= 'a' && p <= 'z') || (p >= '0' && p <= '9') ||
			p == '-' || p == '_' || p == '.' || p == '~')
		{
			*pPos++ = p;
			++nDstLen;
		}
		else
		{
			*pPos++ = '%';
			*pPos++ = HexDigits[p >> 4];
			*pPos++ = HexDigits[p & 0x0f];
			nDstLen += 3;
		}
	}

	char* pTemp = static_cast<char*>(realloc(pResult, nDstLen + 1LL));
	if (pTemp != nullptr)
	{
		pResult = pTemp;
	}
	*(pResult + nDstLen) = '\0';

	return pResult;
}

char* DecodeUri(const char* src)
{
	if (src == nullptr)return nullptr;

	size_t nSrcLen = strlen(src);
	char* pResult = static_cast<char*>(malloc(nSrcLen + 1LL));
	if (pResult == nullptr)return nullptr;

	size_t nPos = 0;
	size_t nLen = 0;
	char* pp = const_cast<char*>(src);

	for (;;)
	{
		char* p = strchr(pp, '%');
		if (p == nullptr)
		{
			nLen = nSrcLen - (pp - src);
			memcpy(pResult + nPos, pp, nLen);
			nPos += nLen;
			break;
		}

		nLen = p - pp;
		memcpy(pResult + nPos, pp, nLen);
		nPos += nLen;
		pp = p + 1;

		char pzBuffer[3]{};
		memcpy(pzBuffer, pp, 2);
		if (isxdigit(static_cast<unsigned char>(pzBuffer[0])) && isxdigit(static_cast<unsigned char>(pzBuffer[1])))
		{
			*(pResult + nPos) = static_cast<char>(strtol(pzBuffer, nullptr, 16));
			++nPos;
			pp += 2;
		}

	}

	char* pTemp = static_cast<char*>(realloc(pResult, nPos + 1LL));
	if (pTemp != nullptr)
	{
		pResult = pTemp;
	}
	*(pResult + nPos) = '\0';

	return pResult;
}