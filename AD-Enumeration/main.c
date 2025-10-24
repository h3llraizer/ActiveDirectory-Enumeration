#include <windows.h>
#include <stdio.h>      // Standard I/O - printf etc
#include <winldap.h>    // LDAP Data-Structures
#include <dsgetdc.h>    // Query domain controller
#include <winber.h>     // parse ldap query results
#include <lm.h>         // 
#include <wtsapi32.h>

#include "Parser.h"
#include "Other.h"

#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "Netapi32.lib")

//BOOL GetSiteName()
//{
//
//    DsGetDcNameA;
//    DsGetSiteNameW;
//
//    return TRUE;
//}

BOOL GetDomainSites(LPCWSTR domainController)
{
    ULONG numberOfSites = 0;
    LPWSTR* siteNames = NULL;
    DWORD result = DsGetDcSiteCoverageW(domainController, &numberOfSites, &siteNames);

    wprintf(L"Number of sites: %lu \n", numberOfSites);

    if (siteNames)
        for (int i = 0; i < numberOfSites; i++)
        {
            wprintf(L"%ls \n", siteNames[i]);
        }
        NetApiBufferFree(siteNames);
    return numberOfSites;
}

BOOL ConfirmDomainJoin(LPCWSTR domainName)
{
    if (domainName == NULL)
    {
        wprintf(L"[!] Domain name not supplied.\n");
        return;
    }

    LPWSTR* nameBuffer = NULL;
    NETSETUP_JOIN_STATUS joinStatus;
    NET_API_STATUS dwResult = NetGetJoinInformation(domainName, &nameBuffer, &joinStatus);
    if (dwResult != NERR_Success)
    {
        wprintf(L"[!] Failed to get domain join info. Error: %lu \n", dwResult);
        return FALSE;
    }

    wprintf(L"[+] Domain join status: ");

    switch (joinStatus) {
    case NetSetupUnknownStatus:
        wprintf(L"NetSetupUnknownStatus\n");
        break;
    case NetSetupUnjoined:
        wprintf(L"NetSetupUnjoined (not joined)\n");
        break;
    case NetSetupWorkgroupName:
        wprintf(L"NetSetupWorkgroupName (workgroup)\n");
        break;
    case NetSetupDomainName:
        wprintf(L"NetSetupDomainName (domain)\n");
        break;
    default:
        wprintf(L"unknown value %d\n", joinStatus);
        break;
    }

    if (nameBuffer)
        NetApiBufferFree(nameBuffer);
}

void GetJoinableOUs(LPCWSTR domainName)
{

    if (domainName == NULL)
    {
        wprintf(L"Domain name not supplied.\n");
        return;
    }

    DWORD ouCount = 0;
    LPWSTR* ous = NULL;
    NET_API_STATUS dwResult = NetGetJoinableOUs(
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
        printf("[!] ldap_init failed\n");
        return FALSE;
    }

    // Set LDAP version
    ldap_set_option(*ld, LDAP_OPT_PROTOCOL_VERSION, (void*)&version);

    // Simple bind (use current Windows credentials if NULL/NULL)
    *result = ldap_bind_sW(*ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (*result != LDAP_SUCCESS) {
        printf("[!] ldap_bind_s failed: %lu\n", *result);
        ldap_unbind(*ld);
        return FALSE;
    }

    return TRUE;
}

BOOL SearchLdap(LDAP* ld, PWCHAR base, PWCHAR searchFilter, PWCHAR* searchAttributes, ULONG* result)
{

    LDAPMessage* res = NULL;
    *result = ldap_search_sW(
        ld,  // session handle
        base,  //  contains the distinguished name of the entry at which to start the search.
        LDAP_SCOPE_SUBTREE,  // Specifies one of the following values to indicate the search scope. search entire tree
        searchFilter,  // redundant when NULL is used for attributes
        NULL,  //attributes // NULL to retrieve all available attributes.
        0,
        &res
    );

    if (*result != LDAP_SUCCESS) {
        printf("[!] ldap_search_s failed: %lu\n", *result);
        ldap_unbind(ld);
        return FALSE;
    }

    printf("[+] Search successful\n");

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

int wmain(int argc, wchar_t** argv, wchar_t** envp)
{
    
    wchar_t FQDN[MAX_PATH]  = { 0 };    // FQDN = Fully Qaulified Domain Name - e.g. corp.local
    wchar_t TLD[MAX_PATH]   = { 0 };    // TLD = Top Level Domain - e.g. .local
    wchar_t SLD[MAX_PATH]   = { 0 };    // SLD = Second Level Domain - e.g. corp
    wchar_t DC[MAX_PATH]    = { 0 };    // DC  = Domain Controller

    PWCHAR base[MAX_PATH] = { 0 };
    PWCHAR searchFilter = L"(objectClass=accounts)";   // search objectClass type
    PWCHAR searchAttributes[] = {  // attributes of the objectClass
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

    if (!GetDomainController(&envp, &DC))
    {
        wprintf(L"Could not retrieve Domain Controller from Process Parameters block.\n");
    }
    else {
        wprintf(L"DomainController: %ls \n", DC);
        GetDomainSites(DC);
    }

    GetJoinableOUs(FQDN);

    swprintf_s(base, 256, L"DC=%ls,DC=%ls", TLD, SLD);

    if (!BindLdap(FQDN, &ld, LDAP_VERSION3, &result)) {
        printf("[!] LDAP Bind failed. Error: %lu \n", result);
        getchar();
        return 1;
    }

    printf("[+] LDAP bind successful\n");

    if (!SearchLdap(ld, base, searchFilter, searchAttributes, &result)) {
        goto cleanup;
    }

    //if (!EnumActiveLoginSessionsViaSMB(DC))
    //{
    //    goto cleanup;
    //}

    //if (!EnumerateShares(DC))
    //{
    //    goto cleanup;
    //}


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