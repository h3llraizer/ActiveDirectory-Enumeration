#define PHNT_VERSION PHNT_WINDOWS_11
#include <phnt_windows.h>
#include <phnt.h>
#include <lm.h>
#include <winldap.h>
#include <wtsapi32.h>
#include <dsgetdc.h>
#include <winber.h>

#include <stdio.h> // Standard I/O library - printf etc

#include "Parser.h"
#include "Other.h"
#include "Structs.h"
#include "AD_DS_defs.h"

NetApi32 NetApi;
WLdap32 WLdap;

BOOL GetDomainSites(LPCWSTR domainController)
{
    ULONG numberOfSites = 0;
    LPWSTR* siteNames = NULL;
    DWORD result = NetApi.DsGetDcSiteCoverageW(domainController, &numberOfSites, &siteNames);

    wprintf(L"Number of sites: %lu \n", numberOfSites);

    if (siteNames)
        for (int i = 0; i < numberOfSites; i++)
        {
            wprintf(L"%ls \n", siteNames[i]);
        }
        NetApi.NetApiBufferFree(siteNames);
    return numberOfSites;
}

BOOL ConfirmDomainJoin(LPCWSTR domainName)
{
    BOOL joined = FALSE;

    if (domainName == NULL)
    {
        wprintf(L"[!] Domain name not supplied.\n");
        return;
    }

    LPWSTR* nameBuffer = NULL;
    NETSETUP_JOIN_STATUS joinStatus;
    NET_API_STATUS dwResult = NetApi.NetGetJoinInformation(domainName, &nameBuffer, &joinStatus);
    if (dwResult != NERR_Success)
    {
        wprintf(L"[!] Failed to get domain join info. Error: %lu \n", dwResult);
        return FALSE;
    }

    wprintf(L"[i] Domain join status: ");

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
        joined = TRUE;
        break;
    default:
        wprintf(L"unknown value %d\n", joinStatus);
        break;
    }

    if (nameBuffer)
        NetApi.NetApiBufferFree(nameBuffer);

    return joined;
}

void GetJoinableOUs(LPCWSTR domainController, LPCWSTR domainName)
{

    if (domainName == NULL || domainController == NULL)
    {
        wprintf(L"Domain name not supplied.\n");
        return;
    }

    DWORD ouCount = 0;
    LPWSTR* ous = NULL;
    NET_API_STATUS dwResult = NetApi.NetGetJoinableOUs(
        domainController,
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

    NetApi.NetApiBufferFree(ous);
}

BOOL BindLdap(PWCHAR domainName, LDAP** ld, ULONG version, ULONG* result)
{
    // Connect to the default LDAP server (local domain controller)
    *ld = WLdap.ldap_initW(domainName, LDAP_PORT); // use LDAP_SSL_PORT for LDAPS
    if (*ld == NULL) {
        wprintf(L"[!] ldap_init failed\n");
        return FALSE;
    }

    // Set LDAP version
    WLdap.ldap_set_option(*ld, LDAP_OPT_PROTOCOL_VERSION, (void*)&version);

    // Simple bind (use current Windows credentials if NULL/NULL)
    *result = WLdap.ldap_bind_sW(*ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (*result != LDAP_SUCCESS) {
        wprintf(L"[!] ldap_bind_s failed: %lu\n", *result);
        WLdap.ldap_unbind(*ld);
        return FALSE;
    }

    return TRUE;
}

BOOL SearchLdap(LDAP* ld, PWCHAR base, PWCHAR searchFilter, PWCHAR* searchAttributes, ULONG* result, LDAPMessage* res)
{
    *result = WLdap.ldap_search_sW(
        ld,  // LDAP session handle *required*
        base,  //  contains the distinguished name of the entry at which to start the search.
        LDAP_SCOPE_SUBTREE,  // Specifies one of the following values to indicate the search scope. search entire tree
        searchFilter,  // redundant when NULL is used for attributes
        searchAttributes,  //attributes // NULL to retrieve all available attributes.
        0,   // attrsONLY - nonzero if only types are required
        res  // res stores the message
    );

    if (*result != LDAP_SUCCESS) {
        printf("[!] ldap_search_s failed: %lu\n", *result);
        return FALSE;
    }

    return TRUE;

}

BOOL ParseLdapMessage(LDAP* ld, LDAPMessage* res){

    if (ld == NULL || res == NULL)
    {
        wprintf(L"[!] Failed to parse LDAP messge. ld or res NULL.\n");
        return FALSE;
    }

    LDAPMessage* entry = NULL;
    for (entry = WLdap.ldap_first_entry(ld, res); entry != NULL; entry = WLdap.ldap_next_entry(ld, entry))
    {
        PWCHAR dn = WLdap.ldap_get_dnW(ld, entry);
        //wprintf(L"%ls", dn);
        WLdap.ldap_memfree(dn);

        // Attributes
        BerElement* ber = NULL;
        PWCHAR attr = WLdap.ldap_first_attributeW(ld, entry, &ber);
        while (attr != NULL)
        {
            struct berval** vals = WLdap.ldap_get_values_lenW(ld, entry, attr);
            if (vals != NULL)
            {
                for (int i = 0; vals[i] != NULL; i++)
                {
                    //wprintf(L"%ls : %hs", attr, vals[i]->bv_val);
                    wprintf(L"\t%hs \n", vals[i]->bv_val);

                }
                WLdap.ldap_value_free_len(vals);
            }
            WLdap.ldap_memfree(attr);
            attr = WLdap.ldap_next_attributeW(ld, entry, ber);
            //wprintf(L"\n");
        }
        if (ber != NULL) WLdap.ber_free(ber, 0);
        //wprintf(L"\n");
    }

    WLdap.ldap_msgfree(res);

    return TRUE;
}

BOOL GetLocalUserGroupMemberships(LDAPSession* session, Domain* domain, Local* local)
{
    BOOL success = FALSE;
    // query local users' group memberships - domain users group ommitted
    LDAPQuery localUserGroupsMemberQuery = { .base = { 0 }, .searchFilter = { 0 }, .searchAttributes = {L"memberOf"}, .response = NULL };

    swprintf_s(localUserGroupsMemberQuery.base, MAX_PATH, L"DC=%ls,DC=%ls", domain->SLD, domain->TLD);  // format the domain parts - in future add handling for subdomain (e.g. branch.domain.com)

    wprintf(L"[i] Query Base: %ws \n", localUserGroupsMemberQuery.base);

    swprintf_s(localUserGroupsMemberQuery.searchFilter, MAX_PATH, L"(&(objectClass=user)(sAMAccountName=%ls))", local->Username);

    wprintf(L"[i] SearchFilter: %ls \n", localUserGroupsMemberQuery.searchFilter);

    if (!SearchLdap(session->ld, localUserGroupsMemberQuery.base, localUserGroupsMemberQuery.searchFilter, localUserGroupsMemberQuery.searchAttributes, &session->result, &localUserGroupsMemberQuery.response)) {
        goto EndOfFunction;
    }

    wprintf(L"[+] LDAP Search Successful.\n");

    if (!ParseLdapMessage(session->ld, localUserGroupsMemberQuery.response))
    {
        goto EndOfFunction;
    }

    success = TRUE;

EndOfFunction:
    return success;
}

BOOL GetLocalMachineGroupMemberships(LDAPSession* session, Domain* domain, Local* local)
{
    BOOL success = FALSE;
    LDAPQuery localMachineGroupsMemberQuery = { .base = { 0 }, .searchFilter = { 0 }, .searchAttributes = {L"memberOf"}, .response = NULL };

    swprintf_s(localMachineGroupsMemberQuery.base, MAX_PATH, L"DC=%ls,DC=%ls", domain->SLD, domain->TLD);  // format the domain elements - in future add handling for subdomain (e.g. branch.domain.com)

    wprintf(L"[i] Query Base: %ws \n", localMachineGroupsMemberQuery.base);

    swprintf_s(localMachineGroupsMemberQuery.searchFilter, MAX_PATH, L"(&(objectClass=computer)(sAMAccountName=%ls$))", local->MachineName);

    wprintf(L"[i] SearchFilter: %ls \n", localMachineGroupsMemberQuery.searchFilter);

    if (!SearchLdap(session->ld, localMachineGroupsMemberQuery.base, localMachineGroupsMemberQuery.searchFilter, localMachineGroupsMemberQuery.searchAttributes, &session->result, &localMachineGroupsMemberQuery.response)) {
        goto EndOfFunction;
    }

    wprintf(L"[+] LDAP Search Successful.\n");

    if (!ParseLdapMessage(session->ld, localMachineGroupsMemberQuery.response))
    {
        goto EndOfFunction;
    }

    success = TRUE;

EndOfFunction:
    return success;
}


BOOL GetDomainUsers(LDAPSession* session, Domain* domain)
{
    BOOL success = FALSE;
    LDAPQuery localMachineGroupsMemberQuery = { .base = { 0 }, .searchFilter = { 0 }, .searchAttributes = {L"sAMAccountName"}, .response = NULL };

    swprintf_s(localMachineGroupsMemberQuery.base, MAX_PATH, L"DC=%ls,DC=%ls", domain->SLD, domain->TLD);  // format the domain elements - in future add handling for subdomain (e.g. branch.domain.com)

    wprintf(L"[i] Query Base: %ws \n", localMachineGroupsMemberQuery.base);

    swprintf_s(localMachineGroupsMemberQuery.searchFilter, MAX_PATH, L"(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)))");

    wprintf(L"[i] SearchFilter: %ls \n", localMachineGroupsMemberQuery.searchFilter);

    if (!SearchLdap(session->ld, localMachineGroupsMemberQuery.base, localMachineGroupsMemberQuery.searchFilter, localMachineGroupsMemberQuery.searchAttributes, &session->result, &localMachineGroupsMemberQuery.response)) {
        goto EndOfFunction;
    }

    wprintf(L"[+] LDAP Search Successful.\n");

    if (!ParseLdapMessage(session->ld, localMachineGroupsMemberQuery.response))
    {
        goto EndOfFunction;
    }

    success = TRUE;

EndOfFunction:
    return success;
}

BOOL ResolveNetApiFunctions()
{
    HMODULE hNetapi32 = LoadLibraryW(L"Netapi32.dll");
    if (hNetapi32 == NULL)
    {
        wprintf(L"Failed to resolve Netapi32.dll. Error: %d \n", GetLastError());
    }

    struct { const char* name; FARPROC* ptr; } functions[] = {
        { "NetApiBufferFree", (FARPROC*)&NetApi.NetApiBufferFree },
        { "DsGetDcSiteCoverageW", (FARPROC*)&NetApi.DsGetDcSiteCoverageW },
        { "NetGetJoinInformation", (FARPROC*)&NetApi.NetGetJoinInformation },
        { "NetGetJoinableOUs", (FARPROC*)&NetApi.NetGetJoinableOUs },
        { "NetShareEnum", (FARPROC*)&NetApi.NetShareEnum}
    };

    for (size_t i = 0; i < sizeof(functions) / sizeof(functions[0]); i++) {
        *functions[i].ptr = GetProcAddress(hNetapi32, functions[i].name);
        if (*functions[i].ptr == NULL) {
            printf("[!] Could not resolve function address for %s. Error: %d\n",
                functions[i].name, GetLastError());
            return FALSE;
        }
    }

    return TRUE;
}

BOOL ResolveWLdapFunctions()
{
    HMODULE hWldap32 = LoadLibraryW(L"wldap32.dll");
    if (hWldap32 == NULL)
    {
        wprintf(L"Could not resolve wldap32.dll. Error: %d \n", GetLastError());
    }

    struct { const char* name; FARPROC* ptr; } functions[] = {
        { "ldap_initW", (FARPROC*)&WLdap.ldap_initW },
        { "ldap_set_option", (FARPROC*)&WLdap.ldap_set_option },
        { "ldap_bind_sW", (FARPROC*)&WLdap.ldap_bind_sW },
        { "ldap_unbind", (FARPROC*)&WLdap.ldap_unbind },
        { "ldap_first_entry", (FARPROC*)&WLdap.ldap_first_entry },
        { "ldap_first_attributeW", (FARPROC*)&WLdap.ldap_first_attributeW },
        { "ldap_next_entry", (FARPROC*)&WLdap.ldap_next_entry},
        { "ldap_get_values_lenW", (FARPROC*)&WLdap.ldap_get_values_lenW },
        { "ldap_get_dnW", (FARPROC*)&WLdap.ldap_get_dnW },
        { "ldap_value_free_len", (FARPROC*)&WLdap.ldap_value_free_len },
        { "ldap_next_attributeW", (FARPROC*)&WLdap.ldap_next_attributeW },
        { "ldap_msgfree", (FARPROC*)&WLdap.ldap_msgfree },
        { "ldap_memfree", (FARPROC*)&WLdap.ldap_memfree },
        { "ldap_search_sW", (FARPROC*)&WLdap.ldap_search_sW },
        { "ber_free", (FARPROC*)&WLdap.ber_free}
    };

    for (size_t i = 0; i < sizeof(functions) / sizeof(functions[0]); i++) {
        *functions[i].ptr = GetProcAddress(hWldap32, functions[i].name);
        if (*functions[i].ptr == NULL) {
            printf("[!] Could not resolve function address for %s. Error: %d\n",
                functions[i].name, GetLastError());
            return FALSE;
        }
    }

    return TRUE;
}

int wmain(int argc, wchar_t** argv, wchar_t** envp)
{

    if (!ResolveNetApiFunctions())
    {
        return 1;
    }

    if (!ResolveWLdapFunctions()) {
        return 1;
    }

    Local local = { .MachineName = { 0 }, .Username = { 0 } };
    Domain domain = { .FQDN = { 0 }, .TLD = { 0 }, .SLD = { 0 }, .DC = { 0 } };
    LDAPSession ldSession = { .ld = NULL, .version = LDAP_VERSION3, .result = NULL};


    if (!GetVariableValueFromName(&envp, L"COMPUTERNAME", &local.MachineName))
    {
        return 1;
    }

    wprintf(L"[i] MachineName: %ls \n", local.MachineName);

    if (!GetVariableValueFromName(&envp, L"USERNAME", &local.Username))
    {
        return 1;
    }

    wprintf(L"[i] Username: %ls \n", local.Username);

    if (!GetDomainName(&envp, &domain.FQDN, &domain.TLD, &domain.SLD))
    {
        // add domain join status query function here as validation
        wprintf(L"[!] Machine is not domain joined.\n");
        if (!ConfirmDomainJoin(domain.FQDN))
        {
            return 0;
        }
    }

    wprintf(L"[i] Full Domain Name: %ls \n", domain.FQDN); 
    wprintf(L"[i] Secondary-Level Domain: %ls\n", domain.SLD);
    wprintf(L"[i] Top-Level Domain: %ls\n", domain.TLD);

    if (!GetVariableValueFromName(&envp, &domain.DC, L"LOGONSERVER"))  // get the domain controller
    {
        wprintf(L"[!] Could not retrieve Domain Controller from Process Parameters block.\n");
    }
    else {
        wprintf(L"[+] DomainController: %ls \n", domain.DC);
    }

    //GetDomainSites(domain.DC); // enumerate the domain sites

    if (!BindLdap(domain.FQDN, &ldSession.ld, ldSession.version, &ldSession.result)) {
        wprintf(L"[!] LDAP Bind failed. Error: %lu \n", ldSession.result);
        return 1;
    }

    wprintf(L"[+] LDAP bind successful\n");

    if (!GetLocalUserGroupMemberships(&ldSession, &domain, &local))
    {
        goto cleanup;
    }

    if (!GetLocalMachineGroupMemberships(&ldSession, &domain, &local))
    {
        goto cleanup;
    }

    if (!GetDomainUsers(&ldSession, &domain))
    {
        goto cleanup;
    }

    if (!EnumerateShares(domain.FQDN))
    {
        goto cleanup;
    }


cleanup:

    if (!ldSession.ld == NULL) WLdap.ldap_unbind(ldSession.ld);  // unbind the ldap connection if one was made

    getchar();  // debugging

    return 0;
}