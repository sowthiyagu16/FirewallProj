#pragma once  
#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <iostream>
#include <vector>
#include <fstream>
#include "stdafx.h"

class TpmSigner
{
public:
    TpmSigner();
    ~TpmSigner();

    bool signfile(const std::string& filePath);

private:
    SECURITY_STATUS status = ERROR_SUCCESS;
    NCRYPT_PROV_HANDLE hProv = 0;
    NCRYPT_KEY_HANDLE hKey = 0;
    const wchar_t* keyName = L"TPM_SignKey";

    // Helper functions
    int SignHashWithTPM(const std::wstring& filePath);
    std::string toHexString(const std::vector<BYTE>& data);
    std::wstring Utf8ToWide(const std::string& utf8);
};