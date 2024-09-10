
#include <Windows.h>

#include <string>
#include <vector>

#include "file_utility.h"

/*
* Macro is used to avoid importing header-only files, and smallen execution file size.
* 1. No macro definition
* => Download resources based on existing episode files.
* 
* 2. NON_ADV_RESOURCE
* => Download files on manifest.
* 
* 3. NON_ADV_RESOURCE + ADV_REQUEST
* => Request episode files using the account's authorisation.
*/

#define NON_ADV_RESOURCE
#define ADV_REQUEST

#ifdef NON_ADV_RESOURCE
#include "md5.h"
#endif

#if defined(NON_ADV_RESOURCE) && defined(ADV_REQUEST)
#include "win_http_session.h"
#include "unix_clock.h"
#include "base64.h"
#include "sha256.h"
#include "hmac.h"
#endif

struct ResourcePath
{
	std::string strFileName;
	std::string strPath;
	std::string strMd5;
};

struct Authorisation
{
	std::string strConsumerKey;
	std::string strConsumerSecret;
	std::string strUserId;
	std::string strToken;
	std::string strSecret;
};

Authorisation g_Auth;
std::string g_strVersion;


/*寝室ファイル保存*/
void DownloadResources(const char* pzFolder, std::vector<ResourcePath> resource_path)
{
	std::string strFolder = CreateWorkFolder("Resource") + pzFolder + "\\/";
	for (size_t i = 0; i < resource_path.size(); ++i)
	{
		ResourcePath r = resource_path.at(i);
		std::string strUrl = "https://tonofura-r-cdn-resource.deepone-online.com/deep_one/download_adv/";
		strUrl += r.strPath + "/" + r.strMd5 + r.strFileName.substr(r.strFileName.size() - 4, 4);
		SaveInternetResourceToFile(strUrl.c_str(), strFolder.c_str(), r.strFileName.c_str(), 0, true);
	}

}
/*寝室資源経路情報読み取り*/
void ReadResourcePathValue(char* src, std::vector<ResourcePath>& resource_path)
{
	char buffer[256]{};
	bool bRet = false;

	ResourcePath r;

	bRet = GetJsonElementValue(src, "fileName", buffer, sizeof(buffer));
	if (bRet)
	{
		r.strFileName = buffer;
	}

	bRet = GetJsonElementValue(src, "path", buffer, sizeof(buffer));
	if (bRet)
	{
		r.strPath = buffer;
	}

	bRet = GetJsonElementValue(src, "md5", buffer, sizeof(buffer));
	if (bRet)
	{
		r.strMd5 = buffer;
	}

	if (r.strFileName.size() > 4)
	{
		resource_path.push_back(r);
	}

}
/*寝室資源経路情報探索*/
void SearchResourcePath(char* src, std::vector<ResourcePath>& resource_path)
{
	char* p = src;
	char* pp = nullptr;
	ExtractJsonArray(&p, "resource", &pp);
	if (pp == nullptr)return;

	p = pp;
	for (;;)
	{
		char* qq = nullptr;
		ExtractJsonObject(&p, nullptr, &qq);
		if (qq == nullptr)break;
		ReadResourcePathValue(qq, resource_path);
		free(qq);
	}

	free(pp);
}
/*保存済み脚本ファイル検索*/
void FindEpisodeFiles(const char* pzFolder, std::vector<std::string>& episodes)
{
	if (pzFolder == nullptr)return;

	WIN32_FIND_DATAA sFindData;

	std::string strFile = std::string(pzFolder) + "*.json";
	HANDLE hFind = ::FindFirstFileA(strFile.c_str(), &sFindData);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (!(sFindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			{
				if (strlen(sFindData.cFileName) > 4)
				{
					episodes.push_back(sFindData.cFileName);
				}
			}
		} while (::FindNextFileA(hFind, &sFindData));
		::FindClose(hFind);
	}

}
/*脚本記載寝室資源取得*/
void GetEpisodeResources()
{
	std::string strFolder = GetFolderBasePath() + "Episode\\/";

	std::vector<std::string> scenarios;

	FindEpisodeFiles(strFolder.c_str(), scenarios);

	for (size_t i = 0; i < scenarios.size(); ++i)
	{
		std::string strFile = strFolder + scenarios.at(i);
		char* buffer = LoadExistingFile(strFile.c_str());
		if (buffer != nullptr)
		{
			std::vector<ResourcePath> resource_path;
			SearchResourcePath(buffer, resource_path);
			DownloadResources(scenarios.at(i).substr(0, scenarios.at(i).size() - 4).c_str(), resource_path);
			free(buffer);
		}
	}

}
#ifdef NON_ADV_RESOURCE
/*一般資源経路算出*/
std::string GetSubPath(const char* hash)
{
	if (hash == nullptr)return std::string();

	std::string strPath;

	std::string strHash = hash;
	if (strHash.size() > 8)
	{
		char buffer[2]{};
		buffer[0] = hash[0];
		if (isxdigit(static_cast<unsigned char>(buffer[0])))
		{
			long lHex = strtol(buffer, nullptr, 16);
			if (lHex < 0x04)
			{
				strPath = strHash.substr(0, 2) + "/" + strHash.substr(4, 2) + "/";
			}
			else if (lHex < 0x08 && lHex >= 0x04)
			{
				strPath = strHash.substr(2, 2) + "/" + strHash.substr(6, 2) + "/" + strHash.substr(0, 2) + "/";
			}
			else if (lHex < 0x0c && lHex >= 0x08)
			{
				strPath = strHash.substr(4, 2) + "/" + strHash.substr(0, 2) + "/" + strHash.substr(6, 2) + "/" + strHash.substr(2, 2) + "/";
			}
			else
			{
				strPath = strHash.substr(6, 2) + "/" + strHash.substr(2, 2) + "/" + strHash.substr(4, 2) + "/" + strHash.substr(0, 2) + "/";
			}
		}
	}

	return strPath;
}
/*一般資源経路取得*/
std::string GetNonAdvPath(const char* hash)
{
	std::string strPath = "https://tonofura-r-cdn-resource.deepone-online.com/deep_one/download_game_hd/" + GetSubPath(hash);
	return strPath;
}
/*一般資源ファイル保存*/
bool DownloadNonAdvResource(const char* folder_path, const char* raw_name, const char* file_name)
{
	if (folder_path == nullptr || raw_name == nullptr)return false;

	std::string strFolder = folder_path;

	std::string strMd5 = md5(std::string("47cd76e43f74bbc2e1baaf194d07e1fa").append(raw_name));
	std::string strExtension = GetExtensionFromFileName(raw_name);
	std::string strUrl = GetNonAdvPath(strMd5.c_str()) + strMd5 + strExtension;
	std::string strFile = file_name == nullptr ? TruncateFileName(raw_name) : file_name + strExtension;

	return SaveInternetResourceToFile(strUrl.c_str(), strFolder.c_str(), strFile.c_str(), 0, false);
}
/*一般資源元ファイル名探索*/
void SearchAssets(char* src, const char* name, std::vector<std::string>& raw_file_names)
{
	if (src == nullptr)return;

	char* p = src;
	char* pp = nullptr;
	ExtractJsonObject(&p, "assets", &pp);
	if (pp == nullptr)return;

	p = pp;
	ReadUpToJsonNameEnd(&p, nullptr);

	std::string strName = "\"";
	if (name != nullptr)
	{
		strName += name;
	}

	std::vector<char> vBuffer(512, '\0');
	for (;;)
	{
		char* q = nullptr;
		ExtractJsonObject(&p, strName.c_str(), &q);
		if (q == nullptr)break;

		char* r = q;
		ReadUpToJsonNameEnd(&r, nullptr, vBuffer.data(), vBuffer.size());
		raw_file_names.push_back(vBuffer.data());

		free(q);
	}

	free(pp);
}
/*予覧ファイル名からID抽出*/
int ExtractStoryIdFromThumbnailFileName(std::string strFile)
{
	if (strFile.empty())return 0;

	std::string str = RemoveFileExtension(TruncateFileName(strFile.c_str()).c_str());

	return ::atoi(str.c_str());
}
/*manifest取り込み*/
std::string LoadManifestFile()
{
	const char* szUrl = "https://tonofura-r-cdn-resource.deepone-online.com/deep_one/download_game_ld/download_res_hash.manifest";
	char* pBuffer = nullptr;
	unsigned long ulSize = 0;
	LoadInternetResourceToBuffer(szUrl, &pBuffer, &ulSize);
	if (pBuffer != nullptr)
	{
		std::string str;
		str.resize(ulSize);
		memcpy(&str[0], pBuffer, ulSize);
		return str;
	}

	return std::string();
}
/*一覧記載資源ファイル保存*/
void DownloadFilesInManifestFile(const char* relative_url, const char* folder_name, int iDepth, const char* filter = nullptr)
{
	std::string strFile = LoadManifestFile();
	if (!strFile.empty())
	{
		std::vector<std::string> fileNames;
		SearchAssets(&strFile[0], relative_url, fileNames);

		std::string strBaseFolder = folder_name == nullptr ? GetFolderBasePath() : CreateWorkFolder(folder_name);

		for (const auto& fileName : fileNames)
		{
			if (filter != nullptr)
			{
				if (fileName.find(filter) == std::string::npos)continue;
			}

			std::string strFolder = CreateFolderBasedOnRelativeUrl(fileName, strBaseFolder, iDepth, false);
			DownloadNonAdvResource(strFolder.c_str(), fileName.c_str(), nullptr);
		}
	}
}
#endif //NON_ADV_RESOURCE
/*----------------------------------------  認証生成用ここから  ----------------------------------------*/
#if defined(NON_ADV_RESOURCE) && defined(ADV_REQUEST)
/*認証情報読み取り*/
void ReadAuthorityFiles()
{
	std::string strFolder = GetFolderBasePath();
	std::string strFile;
	char* buffer = nullptr;
	char element[256]{};
	g_Auth = Authorisation();

	strFile = strFolder + "JsonAsset.json";
	buffer = LoadExistingFile(strFile.c_str());
	if (buffer != nullptr)
	{
		GetJsonElementValue(buffer, "consumerKey", element, sizeof(element));
		g_Auth.strConsumerKey = element;

		GetJsonElementValue(buffer, "consumerSecret", element, sizeof(element));
		g_Auth.strConsumerSecret = element;

		free(buffer);
	}
	strFile = strFolder + "getDmmAccessToken.json";
	buffer = LoadExistingFile(strFile.c_str());
	if (buffer != nullptr)
	{
		GetJsonElementValue(buffer, "userId", element, sizeof(element));
		g_Auth.strUserId = element;

		GetJsonElementValue(buffer, "token", element, sizeof(element));
		g_Auth.strToken = element;

		GetJsonElementValue(buffer, "secret", element, sizeof(element));
		g_Auth.strSecret = element;

		free(buffer);
	}

	strFile = strFolder + "getDmmMakeRequest.json";
	buffer = LoadExistingFile(strFile.c_str());
	if (buffer != nullptr)
	{
		GetJsonElementValue(buffer, "version", element, sizeof(element));
		g_strVersion = element;
		free(buffer);
	}

}

char* TonofuranReplace(const char* src)
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

		if (p == '(' || p == ')' || p == '$' || p == '!' || p == '*' || p == '\'')
		{
			*pPos++ = '%';
			*pPos++ = HexDigits[p >> 4];
			*pPos++ = HexDigits[p & 0x0f];
			nDstLen += 3;
		}
		else
		{
			*pPos++ = p;
			++nDstLen;
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

std::string TonofuranEncode(const char* src)
{
	std::string strEncoded;
	if (src != nullptr)
	{
		char* pUriEncoded = EncodeUri(src);
		if (pUriEncoded != nullptr)
		{
			char* pTonofuranReplaced = TonofuranReplace(pUriEncoded);
			if (pTonofuranReplaced != nullptr)
			{
				strEncoded = pTonofuranReplaced;
				free(pTonofuranReplaced);
			}
			free(pUriEncoded);
		}
	}

	return strEncoded;
}

std::string GetNonce()
{
	static bool bInitialised = false;
	if (!bInitialised)
	{
		::srand(static_cast<unsigned int>(GetUnixTime()));
		bInitialised = true;
	}

	double x = static_cast<double>(::rand()) / static_cast<double>(RAND_MAX);
	/*JavaScript MAX_SAFE_INTEGER*/
	long long llNonce = static_cast<long long>(::floor(x * 9007199254740991));

	return std::to_string(llNonce);
}

std::string EncodeSignature(const char* pzMethod, const char* pzUrl, const char* pzParameter)
{
	std::string strSignature;

	if (pzMethod != nullptr && pzUrl != nullptr)
	{
		std::string strEncodedUrl = TonofuranEncode(pzUrl);
		std::string strEncodedParameter = TonofuranEncode(pzParameter);

		std::string strMsg;
		strMsg += pzMethod;
		strMsg += '&';
		strMsg += strEncodedUrl;
		strMsg += '&';
		strMsg += strEncodedParameter;

		std::string strKey;
		strKey += g_Auth.strConsumerSecret;
		strKey += '&';
		strKey += g_Auth.strSecret;

		std::string strHex = hmac<SHA256>(strMsg, strKey);
		std::string strByte;
		for (size_t i = 0; i < strHex.size(); i += 2)
		{
			strByte.push_back(static_cast<unsigned char>(strtol(strHex.substr(i, 2).c_str(), nullptr, 16)));
		}
		strSignature = base64::to_base64(strByte);
	}

	return strSignature;
}

std::string ChainParameters(std::string strNonce, std::string strTimeStamp)
{
	std::string strParameter;
	strParameter.reserve(512);

	strParameter += "oauth_consumer_key=";
	strParameter += g_Auth.strConsumerKey;
	strParameter += "&oauth_nonce=";
	strParameter += strNonce;
	strParameter += "&oauth_signature_method=HMAC-SHA256";
	strParameter += "&oauth_timestamp=";
	strParameter += strTimeStamp;
	strParameter += "&oauth_token=";
	strParameter += g_Auth.strToken;
	strParameter += "&xoauth_requestor_id=";
	strParameter += g_Auth.strUserId;

	return strParameter;
}

std::wstring CreateAuthorisation(const char* pzMethod, const char* pzUrl)
{
	std::string strAuthorisation;
	strAuthorisation.reserve(512);

	std::string strNonce = GetNonce();
	std::string strTimeStamp = std::to_string(GetUnixTime());
	std::string strSignature = EncodeSignature(pzMethod, pzUrl, ChainParameters(strNonce, strTimeStamp).c_str());

	strAuthorisation += "Authorization: OAuth realm=\"Users\" oauth_token=\"";
	strAuthorisation += g_Auth.strToken;
	strAuthorisation += "\" xoauth_requestor_id=\"";
	strAuthorisation += g_Auth.strUserId;
	strAuthorisation += "\" oauth_consumer_key=\"";
	strAuthorisation += g_Auth.strConsumerKey;
	strAuthorisation += "\" oauth_signature_method=\"HMAC-SHA256\" oauth_nonce=\"";
	strAuthorisation += strNonce;
	strAuthorisation += "\" oauth_timestamp=\"";
	strAuthorisation += strTimeStamp;
	strAuthorisation += "\" oauth_signature=\"";
	strAuthorisation += strSignature;
	strAuthorisation += "\"\r\n";

	return WidenUtf8(strAuthorisation);
}
/*----------------------------------------  認証生成用ここまで  ----------------------------------------*/

/*Example: X-Deep-One-App-Version: {"masterVersion":"1.179.0","webVersion":"1.179.0","apkHotUpdateVersion":"1.179.0"}*/
std::wstring CreateAppVersion()
{
	std::string strVersion;
	strVersion.reserve(128);
	strVersion += "X-Deep-One-App-Version: {\"masterVersion\":\"";
	strVersion += g_strVersion;
	strVersion += "\",\"webVersion\":\"";
	strVersion += g_strVersion;
	strVersion += "\",\"apkHotUpdateVersion\":\"";
	strVersion += g_strVersion;
	strVersion += "\"}\r\n";

	return WidenUtf8(strVersion);
}

/*HTTP POST ヘッダ生成*/
std::wstring CreatePostRequestHeader(const char* pzUrl)
{
	std::wstring wstrHeader;
	std::wstring wstrAuth = CreateAuthorisation("POST", pzUrl);
	std::wstring wstrVersion = CreateAppVersion();

	wstrHeader += L"Accept: application/json;charset=UTF-8\r\n";
	wstrHeader += L"Content-Type: application/json;charset=UTF-8\r\n";
	wstrHeader += wstrAuth;
	wstrHeader += L"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0\r\n";
	wstrHeader += wstrVersion;

	return wstrHeader;
}
/*HTTP ペイロード生成*/
/*Example: {"storyIds":"10435104","adult":1}*/
std::string CreateGetResourcePayload(int id)
{
	std::string strPayload = "{\"storyIds\":\"";
	strPayload += std::to_string(id);
	strPayload += "\",\"adult\":1}";

	return strPayload;
}
/*Example: {"storyId":10271101}*/
std::string CreateAddStoryPayload(int id)
{
	std::string strPayload = "{\"storyId\":";
	strPayload += std::to_string(id);
	strPayload += "}";

	return strPayload;
}
/*Example: {"storyIdArray":[10130404]}*/
std::string CreateReadStoryPayload(int id)
{
	std::string strPayload = "{\"storyIdArray\":[";
	strPayload += std::to_string(id);
	strPayload += "]}";

	return strPayload;
}
/*HTTP POST要求*/
bool RequestHttpPost(std::wstring wstrUrl, std::wstring wstrHeader, std::string strPayload, const char* pzFilePath)
{
	bool bRet = false;

	CWinHttpSession* pSession = new CWinHttpSession();
	if (pSession != nullptr)
	{
		bRet = pSession->Open();
		if (bRet)
		{
			ResponseData r;

			bRet = pSession->RequestPost(wstrUrl.c_str(), wstrHeader.c_str(), strPayload.c_str(), static_cast<DWORD>(strPayload.size()), r);
			if (bRet)
			{
				if (wcsstr(r.header.c_str(), L"HTTP/1.1 200 OK"))
				{
					SaveStringToFile(r.content, pzFilePath);
				}
				else
				{
					printf("Header content:\r\n%S", r.header.c_str());
					printf("Response data:\r\n%s", r.content.c_str());
					bRet = false;
				}
			}
			else
			{
				printf("WinHttp failed; function: %s, code: %ld\r\n", r.error.c_str(), r.ulErrorCode);
			}

		}
		delete pSession;
	}

	return bRet;
}

bool RequestAddStory(int id)
{
	std::wstring wstrUrl = L"https://tonofura-web-r.deepone-online.com/deep-one/api/story/addStory";
	std::wstring wstrHeader = CreatePostRequestHeader(NarrowUtf8(wstrUrl).c_str());
	std::string strPayload = CreateAddStoryPayload(id);

	return RequestHttpPost(wstrUrl, wstrHeader, strPayload, nullptr);
}

bool RequestReadStory(int id)
{
	std::string strFile = GetFolderBasePath() + "readStory.json";
	std::wstring wstrUrl = L"https://tonofura-web-r.deepone-online.com/deep-one/api/story/readStory";
	std::wstring wstrHeader = CreatePostRequestHeader(NarrowUtf8(wstrUrl).c_str());
	std::string strPayload = CreateReadStoryPayload(id);

	return RequestHttpPost(wstrUrl, wstrHeader, strPayload, strFile.c_str());
}

bool RequestGetResource(int id)
{
	std::string strFile = CreateWorkFolder("Episode") + std::to_string(id) + ".json";
	std::wstring wstrUrl = L"https://tonofura-web-r.deepone-online.com/deep-one/api/story/getResource";
	std::wstring wstrHeader = CreatePostRequestHeader(NarrowUtf8(wstrUrl).c_str());
	std::string strPayload = CreateGetResourcePayload(id);

	return RequestHttpPost(wstrUrl, wstrHeader, strPayload, strFile.c_str());
}

bool IsAdded(int id)
{
	bool bRet = false;
	std::string strFile = GetFolderBasePath() + "readStory.json";
	char* buffer = LoadExistingFile(strFile.c_str());
	if (buffer != nullptr)
	{
		std::string strKey = "\"storyId\":" + std::to_string(id) + ",";
		if (strstr(buffer, strKey.c_str()) != nullptr)
		{
			bRet = true;
		}
		free(buffer);
	}

	return bRet;
}
/*寝室資源経路要求*/
bool RequestResourcePathList(int id)
{
	bool bRet = false;

	std::string strFile = CreateWorkFolder("Episode") + std::to_string(id) + ".json";
	if (DoesFilePathExist(strFile.c_str()))return true;

	if (!IsAdded(id))
	{
		RequestAddStory(id);
	}

	if (RequestReadStory(id))
	{
		bRet = RequestGetResource(id);
	}

	return bRet;

}
/*寝室脚本一覧取得*/
void GetEpisodes()
{
	std::string strFile = LoadManifestFile();
	if (!strFile.empty())
	{
		std::vector<std::string> episode_thumbnails;
		SearchAssets(&strFile[0], "gallery/", episode_thumbnails);

		std::string strFolder = CreateWorkFolder("Thumbnail");
		int iBlank = 0;
		for (size_t i = 0; i < episode_thumbnails.size(); ++i)
		{
			bool bRet = DownloadNonAdvResource(strFolder.c_str(), episode_thumbnails.at(i).c_str(), nullptr);
			if (bRet)
			{
				int iStoryId = ExtractStoryIdFromThumbnailFileName(episode_thumbnails.at(i));
				if (iStoryId)
				{
					bRet = RequestResourcePathList(iStoryId);
					bRet ? iBlank = 0 : ++iBlank;
					if (iBlank > 2)break;
				}
			}
		}
	}
}
#endif // NON_ADV_RESOURCE && ADV_REQUEST
int main()
{
#if defined(NON_ADV_RESOURCE) && defined(ADV_REQUEST)
	ReadAuthorityFiles();
	GetEpisodes();
#elif defined (NON_ADV_RESOURCE) && !defined(ADV_REQUEST)
	//DownloadFilesInManifestFile(nullptr, "Manifest", 0);
	/*試験用*/
	DownloadFilesInManifestFile("character/", "Manifest", 0, "spine/");
#else
	GetEpisodeResources();
#endif
}
