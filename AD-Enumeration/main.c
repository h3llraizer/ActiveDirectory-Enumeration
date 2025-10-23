#include <windows.h>
#include <lmserver.h>
#include <lm.h>
#include <stdio.h>
#include <winldap.h>
#include <dsgetdc.h>
#include <winber.h>

#include <wtsapi32.h>

#pragma comment(lib, "Wtsapi32.lib")

#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "Netapi32.lib")

// void GetLANWorkstations() {
//     LPBYTE bufPtr = NULL;
//     DWORD entriesRead = 0, totalEntries = 0;
//
//     NET_API_STATUS status = NetServerEnum(
//         NULL,                     // NULL = current domain
//         100,                      // SERVER_INFO_100
//         &bufPtr,
//         MAX_PREFERRED_LENGTH,
//         &entriesRead,
//         &totalEntries,
//         SV_TYPE_WORKSTATION,      // Only workstations
//         NULL,                      // NULL = current domain
//         NULL                       // resume handle
//     );
//
//     if (status == NERR_Success) {
//         SERVER_INFO_100 *servers = (SERVER_INFO_100*)bufPtr;
//         for (DWORD i = 0; i < entriesRead; ++i) {
//             wprintf(L"Found workstation: %s\n", servers[i].sv100_name);
//         }
//     }
//
//     else {
//         printf("NERR Status: %lu \n", status);
//     }
//
//     if (bufPtr) NetApiBufferFree(bufPtr);
// }
//
// void GetLocalMachineInfo() {
//     LPWKSTA_INFO_100 pBuf = NULL;
//     if (NetWkstaGetInfo(NULL, 100, (LPBYTE*)&pBuf) == NERR_Success) {
//         wprintf(L"Computer: %ls\n", pBuf->wki100_computername);
//         wprintf(L"LAN Group: %ls\n", pBuf->wki100_langroup);
//         wprintf(L"Platform ID: %lu ", pBuf->wki100_platform_id);
//         NetApiBufferFree(pBuf);
//     }
// }
// // Function to find the domain controller
// void FindDomainController(void) {
//     NETSETUP_JOIN_STATUS status;
//     LPWSTR pNetBIOSDomain = NULL;
//     DWORD dwResult;
//
//     dwResult = NetGetJoinInformation(NULL, &pNetBIOSDomain, &status);
//     if (dwResult != NERR_Success) {
//         printf("NetGetJoinInformation failed with error: %lu\n", dwResult);
//         return;
//     }
//
//     if (status != NetSetupDomainName) {
//         printf("This machine is not joined to a domain (status=%d)\n", status);
//         if (pNetBIOSDomain) NetApiBufferFree(pNetBIOSDomain);
//         return;
//     }
//
//     WCHAR dnsDomain[MAX_PATH];
//     DWORD size = MAX_PATH;
//     BOOL dnsSuccess = GetComputerNameExW(ComputerNameDnsDomain, dnsDomain, &size);
//
//     LPWSTR domainToUse = dnsSuccess ? dnsDomain : pNetBIOSDomain;
//
//     wprintf(L"Using domain: %ls\n", domainToUse);
//
//     PDOMAIN_CONTROLLER_INFO pDCInfo = NULL;
//     dwResult = DsGetDcName(
//         NULL,                 // local computer
//         domainToUse,          // DNS domain name if available
//         NULL,                 // Domain GUID
//         NULL,                 // Site name
//         DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME,
//         &pDCInfo
//     );
//
//     if (dwResult == ERROR_SUCCESS) {
//         wprintf(L"Domain Controller: %ls\n", pDCInfo->DomainControllerName);
//         wprintf(L"Domain Name: %ls\n", pDCInfo->DomainName);
//         wprintf(L"Forest Name: %ls\n", pDCInfo->DnsForestName);
//         wprintf(L"DC Address: %ls\n", pDCInfo->DomainControllerAddress);
//         NetApiBufferFree(pDCInfo);
//     } else {
//         printf("DsGetDcName failed with error: %lu (0x%08lX)\n", dwResult, dwResult);
//     }
//
//     if (pNetBIOSDomain) NetApiBufferFree(pNetBIOSDomain);
// }

void GetJoinableOUs(LPCWSTR domainName)
{
    DWORD ouCount = 0;
    LPWSTR* ous = NULL;
    DWORD dwResult = NetGetJoinableOUs(
        NULL,
        domainName,
        NULL,
        NULL,
        &ouCount,
        &ous);

    if (dwResult != NERR_Success) {
        printf("NetGetOUs failed with error: %lu\n", dwResult);
        return;
    }

    printf("Got %lu joinable OUs\n", ouCount);

    for (DWORD i = 0; i < ouCount; i++) {
        wprintf(L"%ls\n", ous[i]);
    }

    NetApiBufferFree(ous);
}

BOOL BindLdap(PWCHAR domainName, LDAP** ld, ULONG version, ULONG* result)
{
    // Connect to the default LDAP server (local domain controller)
    *ld = ldap_initW(domainName, LDAP_PORT); // use LDAP_SSL_PORT for LDAPS
    if (*ld == NULL) {
        printf("[-] ldap_init failed\n");
        return FALSE;
    }

    // Set LDAP version
    ldap_set_option(*ld, LDAP_OPT_PROTOCOL_VERSION, (void*)&version);

    // Simple bind (use current Windows credentials if NULL/NULL)
    *result = ldap_bind_sW(*ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (*result != LDAP_SUCCESS) {
        printf("[-] ldap_bind_s failed: %lu\n", *result);
        ldap_unbind(*ld);
        return FALSE;
    }

    return TRUE;
}

BOOL SearchLdap(LDAP* ld, PWCHAR base, PWCHAR filter, PWCHAR* attributes, ULONG* result)
{

    LDAPMessage* res = NULL;
    *result = ldap_search_sW(
        ld,
        base,
        LDAP_SCOPE_SUBTREE,  // search entire tree
        filter,
        attributes,
        0,
        &res
    );

    if (*result != LDAP_SUCCESS) {
        printf("[!] ldap_search_s failed: %lu\n", *result);
        ldap_unbind(ld);
        return FALSE;
    }

    printf("[+] Search successful\n");
    // printf("X Results: \n");

    LDAPMessage* entry = NULL;
    for (entry = ldap_first_entry(ld, res); entry != NULL; entry = ldap_next_entry(ld, entry))
    {
        PWCHAR dn = ldap_get_dnW(ld, entry);
        wprintf(L"%ls", dn);
        ldap_memfree(dn);

        // Attributes
        BerElement* ber = NULL;
        PWCHAR attr = ldap_first_attributeW(ld, entry, &ber);
        while (attr != NULL)
        {
            struct berval** vals = ldap_get_values_lenW(ld, entry, attr);
            if (vals != NULL)
            {
                for (int i = 0; vals[i] != NULL; i++)
                {
                    wprintf(L"%ls : %hs", attr, vals[i]->bv_val);
                }
                ldap_value_free_len(vals);
            }
            ldap_memfree(attr);
            attr = ldap_next_attributeW(ld, entry, ber);
            wprintf(L"\n");
        }
        if (ber != NULL) ber_free(ber, 0);
        wprintf(L"\n");
    }

    ldap_msgfree(res);

    return TRUE;
}

BOOL EnumActiveLoginSessionsViaSMB()
{
    LPSESSION_INFO_10 pBuf = NULL;
    DWORD entriesRead = 0, totalEntries = 0, resume = 0;

    NET_API_STATUS status = NetSessionEnum(
        L"\\\\DC01",  // server name
        NULL,
        NULL,
        10,
        (LPBYTE*)&pBuf,
        MAX_PREFERRED_LENGTH,
        &entriesRead,
        &totalEntries,
        &resume
    );

    if (status == NERR_Success && pBuf != NULL) {
        for (DWORD i = 0; i < entriesRead; i++) {
            wprintf(L"User: %s, Client: %s\n",
                pBuf[i].sesi10_username,
                pBuf[i].sesi10_cname);
        }
        NetApiBufferFree(pBuf);
    }
    else {
        wprintf(L"Error: %lu\n", status);
    }

    return TRUE;
}

int EnumActiveLoginSessionsViaWTS()
{
    PWTS_SESSION_INFO pSessions = NULL;
    DWORD count = 0;

    if (WTSEnumerateSessions(
        L"\\DC01",
        0,
        1,
        &pSessions,
        &count)) {

        for (DWORD i = 0; i < count; i++) {
            LPTSTR pUser = NULL;
            DWORD bytes;

            if (WTSQuerySessionInformation(
                WTS_CURRENT_SERVER_HANDLE,
                pSessions[i].SessionId,
                WTSUserName,
                &pUser,
                &bytes)) {
                if (pUser && *pUser) {
                    wprintf(L"Session %d: User %s\n",
                        pSessions[i].SessionId, pUser);
                }
                WTSFreeMemory(pUser);
            }
        }
        WTSFreeMemory(pSessions);
    }
    else {
        wprintf(L"WTSEnumerateSessions failed: %lu\n", GetLastError());
    }

    return 0;
}

BOOL GetDomainName(wchar_t*** envp, wchar_t* FQDN, wchar_t* TLD, wchar_t* SLD)
{
    BOOL domainJoined = FALSE;

    for (WCHAR** env = *envp; *env != 0; env++)
    {
        wchar_t envVar[MAX_PATH] = { 0 };
        int varLength = 0;
        for (int i = 0; (*env)[i] != L'='; i++)
        {
            envVar[i] = (*env)[i];
            varLength++;
        }

        envVar[varLength] = L'\0';  // add NULL-terminator

        if (wcscmp(envVar, L"USERDNSDOMAIN") == 0)
        {
            int fqdnLength = 0;
            for (int i = varLength + 1; (*env)[i] != L'\0'; i++)
            {
                FQDN[fqdnLength] = (*env)[i];
                fqdnLength++;
            }

            FQDN[fqdnLength + 1] = L'\0';

            int sldLength = 0;
            int tldLength = 0;
            for (int i = 0; FQDN[i] != L'\0'; i++)
            {
                if (FQDN[i] == L'.')  // . (dot) in the USERDNSDOMAIN indicates this a domain joined machine as otherwise this variable would be a regular hostname (e.g. DESKTOP-4NJN5) where . is not allowed
                {
                    domainJoined = TRUE;
                }

                else if (domainJoined == FALSE && FQDN[i] != L'.')
                {
                    SLD[sldLength] = FQDN[i];
                    sldLength++;

                }

                else if (domainJoined == TRUE && FQDN[i] != L'.')
                {
                    TLD[tldLength] = FQDN[i];
                    tldLength++;
                }
            }

            SLD[sldLength + 1] = L'\0';
            TLD[tldLength + 1] = L'\0';
        }
    }

    return domainJoined;
}

int wmain(int argc, wchar_t** argv, wchar_t** envp)
{
    
    wchar_t FQDN[MAX_PATH]  = { 0 };    // FQDN = Fully Qaulified Domain Name - e.g. corp.local
    wchar_t TLD[MAX_PATH]   = { 0 };    // TLD = Top Level Domain - e.g. .local
    wchar_t SLD[MAX_PATH]   = { 0 };    // SLD = Second Level Domain - e.g. corp

    PWCHAR base[MAX_PATH] = { 0 };
    PWCHAR userSearchFilter = L"(objectClass=user)";   // search objectClass type
    PWCHAR userSearchAttributes[] = {  // attributes of the objectClass
        L"cn",              // common-name
        L"sAMAccountName",  // user-name
        L"memberOf",        // memberOf
        NULL                // 
    };

    //PWCHAR filter = L"(objectClass=computer)";
    //PWCHAR attrs[] = { L"cn", L"dNSHostName", L"operatingSystem", L"operatingSystemVersion", L"lastLogonTimestamp", L"userAccountControl", NULL};

    LDAP* ld = NULL;
    ULONG version = LDAP_VERSION3;  // try to resolve this dynamically by probing the DC
    ULONG result;

    if (!GetDomainName(&envp, &FQDN, &SLD, &TLD))
    {
        wprintf(L"Machine is not domain joined.\n");
        getchar();
        return 0;
    }

    wprintf(L"DomainName: %ls \n", FQDN); 
    wprintf(L"Secondary-Level Domain: %ls len: %Iu \n", SLD, wcslen(SLD));
    wprintf(L"Top-Level Domain: %ls len: %Iu \n", TLD, wcslen(TLD));

    swprintf_s(base, 256, L"DC=%ls,DC=%ls", TLD, SLD);

    if (!BindLdap(FQDN, &ld, LDAP_VERSION3, &result)) {
        printf("[!] LDAP Bind failed. Error: %lu \n", result);
        getchar();
        return 1;
    }

    printf("[+] LDAP bind successful\n");

    if (!SearchLdap(ld, base, userSearchFilter, userSearchAttributes, &result)) {
        goto cleanup;
    }

    GetJoinableOUs(FQDN);


cleanup:

    ldap_unbind(ld);

    getchar();

    return 0;
}

//EnumActiveLoginSessionsViaSMB();
// //
//EnumActiveLoginSessionsViaWTS();

//GetLocalMachineInfo();
// GetLANWorkstations();
// FindDomainController();