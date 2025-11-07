#include "TpmSignVerifierBridge.hxx"
#include "tpmsignverifier.h"
#include <windows.h>
#include <string>

static std::wstring Utf8ToWide(const std::string& utf8)
{
    if (utf8.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    std::wstring wide(size - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wide[0], size);
    return wide;
}

int VerifyFileWithTPM_Utf8(const std::string& logPathUtf8, const std::string& sigPathUtf8) 
{
    std::wstring logPath = Utf8ToWide(logPathUtf8);
    std::wstring sigPath = Utf8ToWide(sigPathUtf8);
    TpmSignVerifier verifier;
    return verifier.VerifyFileWithTPM(logPath, sigPath);
}
