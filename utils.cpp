#include "includes.h"
#include <mscat.h>

std::vector<GenericRule> genericRules;

std::unordered_map<std::string, std::string> known = {
    {"{308046B0AF4A39CB}", "C:\\Program Files\\Mozilla Firefox"},
    {"{E7CF176E110C211B}", "C:\\Program Files (x86)\\Mozilla Firefox"},
    {"{DE61D971-5EBC-4F02-A3A9-6C82895E5C04}", "C:\\Windows\\System32\\AddNewPrograms.exe"},
    {"{724EF170-A42D-4FEF-9F26-B60E846FBA4F}", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools"},
    {"{A520A1A4-1780-4FF6-BD18-167343C5AF16}", "C:\\Users\\%USERNAME%\\AppData\\LocalLow"},
    {"{A305CE99-F527-492B-8B1A-7E76FA98D6E4}", "C:\\Windows\\SoftwareDistribution\\Download"},
    {"{9E52AB10-F80D-49DF-ACB8-4330F5687855}", "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows\\Burn\\Burn"},
    {"{DF7266AC-9274-4867-8D55-3BD661DE872D}", "C:\\Windows\\System32\\appwiz.cpl"},
    {"{D0384E7D-BAC3-4797-8F14-CBA229B392B5}", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools"},
    {"{C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D}", "C:\\ProgramData\\OEM"},
    {"{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs"},
    {"{A4115719-D62E-491D-AA7C-E74B8BE3B067}", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu"},
    {"{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"},
    {"{B94237E7-57AC-4347-9151-B08C6C32D1F7}", "C:\\ProgramData\\Microsoft\\Windows\\Templates"},
    {"{0AC0837C-BBF8-452A-850D-79D08E667CA7}", "C:\\"},
    {"{4BFEFB45-347D-4006-A5BE-AC0CB0567192}", "C:\\Windows\\System32\\wbem"},
    {"{6F0CD92B-2E97-45D1-88FF-B0D186B8DEDD}", "C:\\Windows\\System32\\control.exe /name Microsoft.NetworkAndSharingCenter"},
    {"{56784854-C6CB-462B-8169-88E350ACB882}", "C:\\Users\\%USERNAME%\\Contacts"},
    {"{82A74AEB-AEB4-465C-A014-D097EE346D63}", "C:\\Windows\\System32\\control.exe"},
    {"{2B0F765D-C0E9-4171-908E-08A611B84FF6}", "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows\\INetCookies"},
    {"{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", "C:\\Users\\%USERNAME%\\Desktop"},
    {"{FDD39AD0-238F-46AF-ADB4-6C85480369C7}", "C:\\Users\\%USERNAME%\\Documents"},
    {"{374DE290-123F-4565-9164-39C4925E467B}", "C:\\Users\\%USERNAME%\\Downloads"},
    {"{1777F761-68AD-4D8A-87BD-30B759FA33DD}", "C:\\Users\\%USERNAME%\\Favorites"},
    {"{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}", "C:\\Windows\\Fonts"},
    {"{CAC52C1A-B53D-4EDC-92D7-6B2E8AC19434}", "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows\\Games"},
    {"{054FAE61-4DD8-4787-80B6-090220C4B700}", "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows\\GameExplorer"},
    {"{D9DC8A3B-B784-432E-A781-5A1130A75963}", "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows\\History"},
    {"{4D9F7874-4E0C-4904-967B-40B0D20C3E4B}", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Network Shortcuts"},
    {"{352481E8-33BE-4251-BA85-6007CAEDCF9D}", "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows\\INetCache"},
    {"{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}", "C:\\Users\\%USERNAME%\\Links"},
    {"{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}", "C:\\Users\\%USERNAME%\\AppData\\Local"},
    {"{2A00375E-224C-49DE-B8D1-440DF7EF3DDC}", "C:\\Windows\\resources"},
    {"{4BD8D571-6D19-48D3-BE97-422220080E43}", "C:\\Users\\%USERNAME%\\Music"},
    {"{C5ABBF53-E17F-4121-8900-86626FC2C973}", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Network Shortcuts"},
    {"{D20BEEC4-5CA8-4905-AE3B-BF251EA09B53}", "C:\\Windows\\System32\\control.exe /name Microsoft.NetworkAndSharingCenter"},
    {"{2C36C0AA-5812-4B87-BFD0-4CD0DFB19B39}", "C:\\Users\\%USERNAME%\\Pictures\\Original Images"},
    {"{69D2CF90-FC33-4FB7-9A0C-EBB0F0FCB43C}", "C:\\Users\\%USERNAME%\\Pictures"},
    {"{33E28130-4E1E-4676-835A-98395C3BC3BB}", "C:\\Users\\%USERNAME%\\Pictures"},
    {"{DE92C1C7-837F-4F69-A3BB-86E631204A23}", "C:\\Users\\%USERNAME%\\Music\\Playlists"},
    {"{76FC4E2D-D6AD-4519-A663-37BD56068185}", "C:\\Windows\\System32\\control.exe /name Microsoft.Printers"},
    {"{9274BD8D-CFD1-41C3-B35E-B13F55A758F4}", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Printer Shortcuts"},
    {"{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "C:\\Users\\%USERNAME%"},
    {"{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}", "C:\\ProgramData"},
    {"{905E63B6-C1BF-494E-B29C-65B732D3D21A}", "C:\\Program Files"},
    {"{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}", "C:\\Program Files\\Common Files"},
    {"{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}", "C:\\Program Files\\Common Files"},
    {"{DE974D24-D9C6-4D3E-BF91-F4455120B917}", "C:\\Program Files (x86)\\Common Files"},
    {"{6D809377-6AF0-444B-8957-A3773F02200E}", "C:\\Program Files"},
    {"{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", "C:\\Program Files (x86)"},
    {"{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs"},
    {"{DFDF76A2-C82A-4D63-906A-5644AC457385}", "C:\\Users\\Public"},
    {"{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}", "C:\\Users\\Public\\Desktop"},
    {"{ED4824AF-DCE4-45A8-81E2-FC7965083634}", "C:\\Users\\Public\\Documents"},
    {"{3D644C9B-1FB8-4F30-9B45-F670235F79C0}", "C:\\Users\\Public\\Downloads"},
    {"{DEBF2536-E1A8-4C59-B6A2-414586476AEA}", "C:\\Users\\Public\\Documents\\GameTasks"},
    {"{3214FAB5-9757-4298-BB61-92A9DEAA44FF}", "C:\\Users\\Public\\Music"},
    {"{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}", "C:\\Users\\Public\\Pictures"},
    {"{2400183A-6185-49FB-A2D8-4A392A602BA3}", "C:\\Users\\Public\\Videos"},
    {"{52A4F021-7B75-48A9-9F6B-4B87A210BC8F}", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch"},
    {"{AE50C081-EBD2-438A-8655-8A092E34987A}", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Recent"},
    {"{BD85E001-112E-431E-983B-7B15AC09FFF1}", "C:\\Users\\Public\\Recorded TV"},
    {"{B7534046-3ECB-4C18-BE4E-64CD4CB7D6AC}", "C:\\$Recycle.Bin"},
    {"{8AD10C31-2ADB-4296-A8F7-E4701232C972}", "C:\\Windows\\Resources"},
    {"{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}", "C:\\Users\\%USERNAME%\\AppData\\Roaming"},
    {"{B250C668-F57D-4EE1-A63C-290EE7D1AA1F}", "C:\\Users\\Public\\Music\\Sample Music"},
    {"{C4900540-2379-4C75-844B-64E6FAF8716B}", "C:\\Users\\Public\\Pictures\\Sample Pictures"},
    {"{15CA69B3-30EE-49C1-ACE1-6B5EC372AFB5}", "C:\\Users\\Public\\Music\\Sample Playlists"},
    {"{859EAD94-2E85-48AD-A71A-0969CB56A6CD}", "C:\\Users\\Public\\Videos\\Sample Videos"},
    {"{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}", "C:\\Users\\%USERNAME%\\Saved Games"},
    {"{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}", "C:\\Users\\%USERNAME%\\Searches"},
    {"{EE32E446-31CA-4ABA-814F-A5EBD2FD6D5E}", "C:\\Windows\\System32"},
    {"{98EC0E18-2098-4D44-8644-66979315A281}", "C:\\Windows\\System32"},
    {"{190337D1-B8CA-4121-A639-6D472D16972A}", "C:\\Users\\%USERNAME%\\Searches"},
    {"{8983036C-27C0-404B-8F08-102D10DCFD74}", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\SendTo"},
    {"{7B396E54-9EC5-4300-BE0A-2482EBAE1A26}", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Sidebar\\Gadgets"},
    {"{A75D362E-50FC-4FB7-AC2C-A8BEAA314493}", "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows Sidebar\\Gadgets"},
    {"{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu"},
    {"{B97D20BB-F46A-4C97-BA10-5E3608430854}", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"},
    {"{43668BF8-C14E-49B2-97C9-747784D784B7}", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Sync Center"},
    {"{289A9A43-BE44-4057-A41B-587A76D7E7F9}", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Sync Center\\Sync Results"},
    {"{0F214138-B1D3-4A90-BBA9-27CBC0C5389A}", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Sync Center\\Sync Setup"},
    {"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", "C:\\Windows\\System32"},
    {"{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}", "C:\\Windows\\SysWOW64"},
    {"{A63293E8-664E-48DB-A079-DF759E0509F7}", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Templates"},
    {"{5B3749AD-B49F-49C1-83EB-15370FBD4882}", "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows\\TreeProperties"},
    {"{0762D272-C50A-4BB0-A382-697DCD729B80}", "C:\\Users"},
    {"{F3CE0F7C-4901-4ACC-8648-D5D44B04EF8F}", "C:\\Users\\%USERNAME%"},
    {"{18989B1D-99B5-455B-841C-AB7C74E4DDFC}", "{C:\\Users\\%USERNAME%\\Videos"},
    {"F38BF404-1D43-42F2-9305-67DE0B28FC23}",  "C:\\Windows"}
};

std::string convertToPath(const std::string& path) {
    for (const auto& entry : known) {
        if (path.find(entry.first) != std::string::npos) {
            std::string newPath = path;
            newPath.replace(newPath.find(entry.first), entry.first.length(), entry.second);
            return newPath; 
        }
    }
    return path;
}

bool isAPath(const std::string& path) {
    return path.length() > 0 && (path[0] == ':' || (path.length() > 1 && path[1] == ':'));
}

static bool VerifyFileViaCatalog(LPCWSTR filePath)
{
    HANDLE hCatAdmin = NULL;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
        return false;

    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    DWORD dwHashSize = 0;
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, NULL, 0))
    {
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    BYTE* pbHash = new BYTE[dwHashSize];
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, pbHash, 0))
    {
        delete[] pbHash;
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    CloseHandle(hFile);

    CATALOG_INFO catInfo = { 0 };
    catInfo.cbStruct = sizeof(catInfo);

    HANDLE hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, NULL);
    bool isCatalogSigned = false;

    while (hCatInfo && CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0))
    {
        WINTRUST_CATALOG_INFO wtc = {};
        wtc.cbStruct = sizeof(wtc);
        wtc.pcwszCatalogFilePath = catInfo.wszCatalogFile;
        wtc.pbCalculatedFileHash = pbHash;
        wtc.cbCalculatedFileHash = dwHashSize;
        wtc.pcwszMemberFilePath = filePath;

        WINTRUST_DATA wtd = {};
        wtd.cbStruct = sizeof(wtd);
        wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
        wtd.pCatalog = &wtc;
        wtd.dwUIChoice = WTD_UI_NONE;
        wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wtd.dwProvFlags = 0;
        wtd.dwStateAction = WTD_STATEACTION_VERIFY;

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG res = WinVerifyTrust(NULL, &action, &wtd);

        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &action, &wtd);

        if (res == ERROR_SUCCESS)
        {
            isCatalogSigned = true;
            break;
        }
        hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, &hCatInfo);
    }

    if (hCatInfo)
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);

    CryptCATAdminReleaseContext(hCatAdmin, 0);
    delete[] pbHash;

    return isCatalogSigned;
}

std::string getDigitalSignature(const std::string& filePath) {
    WCHAR wideFilePath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, filePath.c_str(), -1, wideFilePath, MAX_PATH);

    if (GetFileAttributesW(wideFilePath) == INVALID_FILE_ATTRIBUTES) {
        return "Deleted";
    }

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = wideFilePath;

    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.pFile = &fileInfo;

    LONG status = WinVerifyTrust(NULL, &guidAction, &winTrustData);

    std::string result = "Not signed";

    PCCERT_CONTEXT signingCert = nullptr;
    if (status == ERROR_SUCCESS) {
        result = "Signed";

        auto pProvData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
        if (pProvData) {
            auto nonConstData = const_cast<CRYPT_PROVIDER_DATA*>(pProvData);
            auto pProvSigner = WTHelperGetProvSignerFromChain(nonConstData, 0, FALSE, 0);
            if (pProvSigner) {
                auto pProvCert = WTHelperGetProvCertFromChain(pProvSigner, 0);
                if (pProvCert && pProvCert->pCert) {
                    signingCert = pProvCert->pCert;
                    char subjName[256] = {};
                    CertNameToStrA(
                        signingCert->dwCertEncodingType,
                        &signingCert->pCertInfo->Subject,
                        CERT_X500_NAME_STR,
                        subjName,
                        sizeof(subjName)
                    );
                    std::string subj(subjName);
                    std::transform(subj.begin(), subj.end(), subj.begin(), ::tolower);
                    static const char* cheats[] = {
                        "manthe industries, llc",
                        "slinkware",
                        "amstion limited",
                    };
                    for (auto c : cheats) {
                        if (subj.find(c) != std::string::npos) {
                            result = "Cheat Signature";
                            break;
                        }
                    }
                }
            }
        }
    }
    else {
        if (VerifyFileViaCatalog(wideFilePath)) {
            result = "Signed";
        }
    }

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &guidAction, &winTrustData);

    if (signingCert) {
        DWORD hashLen = 0;
        if (CertGetCertificateContextProperty(signingCert, CERT_SHA1_HASH_PROP_ID, nullptr, &hashLen)) {
            std::vector<BYTE> hash(hashLen);
            if (CertGetCertificateContextProperty(signingCert, CERT_SHA1_HASH_PROP_ID, hash.data(), &hashLen)) {
                CRYPT_HASH_BLOB blob = { hashLen, hash.data() };

                static const LPCWSTR storeNames[] = {
                    L"MY",                    // Personal
                    L"Root",                  // Trusted Root CAs
                    L"Trust",                 // Enterprise Trust
                    L"CA",                    // Intermediate CAs
                    L"UserDS",                // Active Directory User Object
                    L"TrustedPublisher",      // Trusted Publishers
                    L"Disallowed",            // Untrusted Certificates
                    L"AuthRoot",              // Third-Party Root CAs
                    L"TrustedPeople",         // Trusted People
                    L"ClientAuthIssuer",      // Client Authentication Issuers
                    L"CertificateEnrollment", // Certificate Enrollment Requests
                    L"SmartCardRoot"          // Smart Card Trusted Roots
                };

                const DWORD contexts[] = {
                    CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
                    CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG
                };

                bool foundAnywhere = false;
                for (DWORD ctx : contexts) {
                    for (auto storeName : storeNames) {
                        HCERTSTORE hStore = CertOpenStore(
                            CERT_STORE_PROV_SYSTEM_W,
                            0,
                            NULL,
                            ctx,
                            storeName
                        );
                        if (!hStore)
                            continue;

                        PCCERT_CONTEXT found = CertFindCertificateInStore(
                            hStore,
                            signingCert->dwCertEncodingType,
                            0,
                            CERT_FIND_SHA1_HASH,
                            &blob,
                            NULL
                        );
                        if (found) {
                            foundAnywhere = true;
                            CertFreeCertificateContext(found);
                        }
                        CertCloseStore(hStore, 0);
                        if (foundAnywhere) break;
                    }
                    if (foundAnywhere) break;
                }

                if (foundAnywhere) {
                    result = "Fake Signature";
                }
            }
        }
    }

    return result;
}

void addGenericRule(const std::string& name, const std::string& rule) {
    genericRules.push_back({ name, rule });
}

void initializeGenericRules() {
    addGenericRule("Generic A", R"(
import "pe"
rule A
{
    strings:
        $a = /clicker/i ascii wide
        $b = /autoclick/i ascii wide
    condition:
        pe.is_pe and
        any of them
}
)");

    addGenericRule("Specifics A", R"(
rule sA
{
    strings:
        $a = /Exodus\.codes/i ascii wide
        $b = /slinky\.gg/i ascii wide
        $c = /slinkyhook\.dll/i ascii wide
        $d = /slinky_library\.dll/i ascii wide
        $e = /\[!\] Failed to find Vape jar/i ascii wide
        $f = /Vape Launcher/i ascii wide
        $g = /vape\.gg/i ascii wide
        $h = /C:\\Users\\PC\\Desktop\\Cleaner-main\\obj\\x64\\Release\\WindowsFormsApp3\.pdb/i ascii wide
        $i = /discord\.gg\/advantages/i ascii wide
        $j = /String cleaner/i ascii wide
        $k = /Open Minecraft, then try again\./i ascii wide
        $l = /The clicker code was done by Nightbot\. I skidded it :\)/i ascii wide
        $m = /PE injector/i ascii wide
        $n = /name="SparkCrack\.exe"/i ascii wide
        $o = /starlight v1\.0/i ascii wide
        $p = /Sapphire LITE Clicker/i ascii wide
        $q = /Striker\.exe/i ascii wide
        $r = /Cracked by Kangaroo/i ascii wide
        $s = /Monolith Lite/i ascii wide
        $t = /B\.fagg0t0/i ascii wide
        $u = /B\.fag0/i ascii wide
        $v = /\.\fag1/i ascii wide
        $w = /dream-injector/i ascii wide
        $x = /C:\\Users\\Daniel\\Desktop\\client-top\\x64\\Release\\top-external\.pdb/i ascii wide
        $y = /C:\\Users\\Daniel\\Desktop\\client-top\\x64\\Release\\top-internal\.pdb/i ascii wide
        $z = /UNICORN CLIENT/i ascii wide
        $aa = /Adding delay to Minecraft/i ascii wide
        $ab = /rightClickChk\.BackgroundImage/i ascii wide
        $ac = /UwU Client/i ascii wide
        $ad = /lithiumclient\.wtf/i ascii wide
        $ae = /breeze\.rip/i ascii wide
        $af = /breeze\.dll/i ascii wide
        $ag = /Failed injecting dll/i ascii wide
        $ah = /Breeze\.InjectScreen/i ascii wide
    condition:
        pe.is_pe and
        any of them
}
)");

    // MAS
}

int yara_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        std::vector<std::string>* matched_rules = (std::vector<std::string>*)user_data;
        matched_rules->push_back(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

void compiler_error_callback(int error_level, const char* file_name, int line_number, const YR_RULE* rule, const char* message, void* user_data) {
    fprintf(stderr, "Error: %s at line %d: %s\n", file_name ? file_name : "N/A", line_number, message);
}

bool scan_with_yara(const std::string& path, std::vector<std::string>& matched_rules) {
    YR_COMPILER* compiler = NULL;
    YR_RULES* rules = NULL;
    int result = yr_initialize();
    if (result != ERROR_SUCCESS) return false;

    result = yr_compiler_create(&compiler);
    if (result != ERROR_SUCCESS) {
        yr_finalize();
        return false;
    }

    yr_compiler_set_callback(compiler, compiler_error_callback, NULL);

    for (const auto& rule : genericRules) {
        result = yr_compiler_add_string(compiler, rule.rule.c_str(), NULL);
        if (result != 0) {
            yr_compiler_destroy(compiler);
            yr_finalize();
            return false;
        }
    }

    result = yr_compiler_get_rules(compiler, &rules);
    if (result != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        yr_finalize();
        return false;
    }

    result = yr_rules_scan_file(rules, path.c_str(), 0, yara_callback, &matched_rules, 0);

    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();

    return !matched_rules.empty();
}
