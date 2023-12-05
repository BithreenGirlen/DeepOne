#ifndef FILE_UTILITY_H_
#define FILE_UTILITY_H_

#include <string>


/*ÉtÉ@ÉCÉãëÄçÏån*/

std::string GetFolderBasePath();
std::string CreateWorkFolder(const char* folder_name);
std::string CreateNestedWorkFolder(std::string strRelativePath);
std::string CreateFolderBasedOnRelativeUrl(std::string strUrl, std::string strBaseFolder, int iDepth, bool bBeFilePath);

char* LoadExistingFile(const char* file_path);
bool SaveNullTerminatedStringToFile(char* data, const char* file_path);
void SaveStringToFile(std::string data, const char* file_path);
bool DoesFilePathExist(const char* file_path);

/*ìdéqñ‘ån*/

bool SaveInternetResourceToFile(const char* url, const char* folder, const char* file_name, unsigned long nMinFileSize, bool bFolderCreation);

/*ï∂éöóÒëÄçÏån*/

bool ExtractJsonObject(char* src, const char* name, char** dst);
bool ExtractJsonArray(char* src, const char* name, char** dst);
bool GetJsonElementValue(char* src, const char* name, char* dst, size_t dst_size);

std::wstring WidenUtf8(std::string str);
std::string NarrowUtf8(std::wstring wstr);

char* ReplaceString(char* src, const char* pzOld, const char* pzNew);

std::string GetFileNameFromFilePath(const char* path);
std::string GetExtensionFromFileName(const char* file_name);
std::string TruncateFileName(const char* file_name);
std::string RemoveFileExtension(const char* file_name);

char* EncodeUri(const char* src);
char* DecodeUri(const char* src);

#endif //FILE_UTILITY_H_