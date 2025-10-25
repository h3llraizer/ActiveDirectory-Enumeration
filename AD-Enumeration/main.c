#include <windows.h>
#include <stdio.h>      // Standard I/O - printf etc
#include <winldap.h>    // LDAP Data-Structures
#include <dsgetdc.h>    // Query domain controller
#include <winber.h>     // parse ldap query results
#include <lm.h>         // 
#include <wtsapi32.h>

#include "Parser.h"
#include "Other.h"
#include "Structs.h"

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
    BOOL joined = FALSE;

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
        NetApiBufferFree(nameBuffer);

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
    NET_API_STATUS dwResult = NetGetJoinableOUs(
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

    NetApiBufferFree(ous);
}

BOOL BindLdap(PWCHAR domainName, LDAP** ld, ULONG version, ULONG* result)
{
    // Connect to the default LDAP server (local domain controller)
    *ld = ldap_initW(domainName, LDAP_PORT); // use LDAP_SSL_PORT for LDAPS
    if (*ld == NULL) {
        wprintf(L"[!] ldap_init failed\n");
        return FALSE;
    }

    // Set LDAP version
    ldap_set_option(*ld, LDAP_OPT_PROTOCOL_VERSION, (void*)&version);

    // Simple bind (use current Windows credentials if NULL/NULL)
    *result = ldap_bind_sW(*ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (*result != LDAP_SUCCESS) {
        wprintf(L"[!] ldap_bind_s failed: %lu\n", *result);
        ldap_unbind(*ld);
        return FALSE;
    }

    return TRUE;
}

BOOL SearchLdap(LDAP* ld, PWCHAR base, PWCHAR searchFilter, PWCHAR* searchAttributes, ULONG* result, LDAPMessage* res)
{
    *result = ldap_search_sW(
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
    for (entry = ldap_first_entry(ld, res); entry != NULL; entry = ldap_next_entry(ld, entry))
    {
        PWCHAR dn = ldap_get_dnW(ld, entry);
        //wprintf(L"%ls", dn);
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
                    //wprintf(L"%ls : %hs", attr, vals[i]->bv_val);
                    wprintf(L"%hs \n", vals[i]->bv_val);

                }
                ldap_value_free_len(vals);
            }
            ldap_memfree(attr);
            attr = ldap_next_attributeW(ld, entry, ber);
            //wprintf(L"\n");
        }
        if (ber != NULL) ber_free(ber, 0);
        //wprintf(L"\n");
    }

    ldap_msgfree(res);

    return TRUE;
}

BOOL GetLocalUserGroupMemberships(LDAPSession* session, Domain* domain, Local* localInfo)
{
    BOOL success = FALSE;
    // query local users' group memberships - domain users group ommitted
    LDAPQuery localUserGroupsMemberQuery = { .base = { 0 }, .searchFilter = { 0 }, .searchAttributes = {L"memberOf"}, .response = NULL };

    swprintf_s(localUserGroupsMemberQuery.base, MAX_PATH, L"DC=%ls,DC=%ls", domain->SLD, domain->TLD);  // format the domain parts - in future add handling for subdomain (e.g. branch.domain.com)

    wprintf(L"[i] Query Base: %ws \n", localUserGroupsMemberQuery.base);

    swprintf_s(localUserGroupsMemberQuery.searchFilter, MAX_PATH, L"(&(objectClass=user)(sAMAccountName=%ls))", localInfo->Username);

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

BOOL GetLocalMachineGroupMemberships(LDAPSession* session, Domain* domain, Local* localInfo)
{
    BOOL success = FALSE;
    // query local users' group memberships - domain users group ommitted
    LDAPQuery localMachineGroupsMemberQuery = { .base = { 0 }, .searchFilter = { 0 }, .searchAttributes = {L"memberOf"}, .response = NULL };

    swprintf_s(localMachineGroupsMemberQuery.base, MAX_PATH, L"DC=%ls,DC=%ls", domain->SLD, domain->TLD);  // format the domain parts - in future add handling for subdomain (e.g. branch.domain.com)

    wprintf(L"[i] Query Base: %ws \n", localMachineGroupsMemberQuery.base);

    swprintf_s(localMachineGroupsMemberQuery.searchFilter, MAX_PATH, L"(&(objectClass=computer)(sAMAccountName=%ls$))", localInfo->MachineName);

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

int wmain(int argc, wchar_t** argv, wchar_t** envp)
{

    Local local = { .MachineName = { 0 }, .Username = { 0 } };
    Domain domain = { .FQDN = { 0 }, .TLD = { 0 }, .SLD = { 0 }, .DC = { 0 } };
    LDAPSession ldSession = { .ld = NULL, .version = LDAP_VERSION3, .result = NULL};


    if (!GetVariableValueFromName(&envp, L"COMPUTERNAME", &local.MachineName))
    {
        return 1;
    }

    wprintf(L"MachineName: %ls \n", local.MachineName);

    if (!GetVariableValueFromName(&envp, L"USERNAME", &local.Username))
    {
        return 1;
    }

    wprintf(L"Username: %ls \n", local.Username);

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

    if (!GetDomainController(&envp, &domain.DC))
    {
        wprintf(L"[!] Could not retrieve Domain Controller from Process Parameters block.\n");
    }
    else {
        wprintf(L"[+] DomainController: %ls \n", domain.DC);
        GetDomainSites(domain.DC);
    }

    if (!BindLdap(domain.FQDN, &ldSession.ld, ldSession.version, &ldSession.result)) {
        wprintf(L"[!] LDAP Bind failed. Error: %lu \n", ldSession.result);
        return 1;
    }

    wprintf(L"[+] LDAP bind successful\n");

    getchar();

    GetLocalUserGroupMemberships(&ldSession, &domain, &local);

    GetLocalMachineGroupMemberships(&ldSession, &domain, &local);


cleanup:

    if (!ldSession.ld == NULL) ldap_unbind(ldSession.ld);  // unbind the ldap connection if one was made

    getchar();  // debugging

    return 0;
}