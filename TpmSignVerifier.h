#pragma once

#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <iostream>
#include <fstream>
#include <vector>
#include "stdafx.h"

class TpmSignVerifier
{
public:
    TpmSignVerifier();
    ~TpmSignVerifier();
    int VerifyFileWithTPM(const std::wstring& logPath, const std::wstring& sigPath);
    std::vector<BYTE> HexToBytes(const std::string& hex);
};

