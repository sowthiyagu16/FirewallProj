#include "TpmSignVerifier.h"
#include <string> 


#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")

std::string WideToUtf8(const std::wstring& wstr)
{
    if (wstr.empty()) return std::string();

    int sizeNeeded = WideCharToMultiByte(
        CP_UTF8, 0,
        wstr.c_str(), (int)wstr.size(),
        nullptr, 0, nullptr, nullptr);

    std::string result(sizeNeeded, 0);
    WideCharToMultiByte(
        CP_UTF8, 0,
        wstr.c_str(), (int)wstr.size(),
        &result[0], sizeNeeded, nullptr, nullptr);

    return result;
}

TpmSignVerifier::TpmSignVerifier()
{

}

TpmSignVerifier::~TpmSignVerifier()
{

}

int TpmSignVerifier::VerifyFileWithTPM(const std::wstring& logPath, const std::wstring& sigPath)
{
    SECURITY_STATUS status;
    NCRYPT_PROV_HANDLE hProv = 0;
    NCRYPT_KEY_HANDLE hKey = 0;
    const wchar_t* keyName = L"TPM_SignKey";

    // 1️⃣ Open TPM provider and key
    status = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
    if (status != ERROR_SUCCESS) {
        std::cerr << "OpenStorageProvider failed: 0x" << std::hex << status << "\n";
        return 1;
    }

    status = NCryptOpenKey(hProv, &hKey, keyName, 0, 0);
    if (status != ERROR_SUCCESS) {
        std::cerr << "OpenKey failed: 0x" << std::hex << status << "\n";
        NCryptFreeObject(hProv);
        return 1;
    }

    // 2️⃣ Hash the .log file using SHA-256
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObject = 0, cbData = 0;
    std::vector<BYTE> hash(32);
    PBYTE pbHashObject = NULL;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status != ERROR_SUCCESS) {
        std::cerr << "BCryptOpenAlgorithmProvider failed: 0x" << std::hex << status << "\n";
        return 1;
    }

    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);

    BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);

    std::ifstream file(logPath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open log file.\n";
        return 1;
    }

    std::vector<char> buffer(4096);
    while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
        BCryptHashData(hHash, (PUCHAR)buffer.data(), (ULONG)file.gcount(), 0);
    }
    BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    HeapFree(GetProcessHeap(), 0, pbHashObject);

    // 3️⃣ Load the signature
    std::ifstream sigFile(sigPath);
    if (!sigFile.is_open()) {
        std::cerr << "Failed to open signature file.\n";
        return 1;
    }

    std::string hexSignature((std::istreambuf_iterator<char>(sigFile)),
        std::istreambuf_iterator<char>());
    sigFile.close();

    // remove newlines or spaces if present
    hexSignature.erase(remove_if(hexSignature.begin(), hexSignature.end(), ::isspace), hexSignature.end());

    // convert hex → bytes
    std::vector<BYTE> signature = HexToBytes(hexSignature);

    BCRYPT_PKCS1_PADDING_INFO padInfo = { BCRYPT_SHA256_ALGORITHM };

    // 4️⃣ Verify signature
    status = NCryptVerifySignature(
        hKey,
        &padInfo,                // no pad info for TPM keys
        hash.data(),
        (DWORD)hash.size(),
        signature.data(),
        (DWORD)signature.size(),
        BCRYPT_PAD_PKCS1);

    if (status == ERROR_SUCCESS) {
        std::cout << "Signature verification SUCCESS for: "
            << WideToUtf8(logPath) << "\n";
    }
    else {
        std::cout << "Signature INVALID for: " << WideToUtf8(logPath) << "\n";
    }

    NCryptFreeObject(hKey);
    NCryptFreeObject(hProv);
    return 0;
}


std::vector<BYTE> TpmSignVerifier::HexToBytes(const std::string& hex)
{
    std::vector<BYTE> bytes;
    bytes.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2)
    {
        char high = hex[i];
        char low = (i + 1 < hex.size()) ? hex[i + 1] : '0';
        if (!isxdigit(high) || !isxdigit(low))
            break;
        BYTE value = (BYTE)((std::stoi(std::string() + high + low, nullptr, 16)) & 0xFF);
        bytes.push_back(value);
    }
    return bytes;
}