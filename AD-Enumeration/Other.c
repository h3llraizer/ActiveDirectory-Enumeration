#pragma once
#include <windows.h>
#include <stdio.h>
#include <lmserver.h>
#include <lm.h>
#include <wtsapi32.h>
#include "Other.h"

#pragma comment(lib, "Wtsapi32.lib")

BOOL EnumerateShares(LPWSTR server)
{
    LPSHARE_INFO_1 pBuf = NULL;

    DWORD entriesRead = 0, totalEntries = 0, resume = 0;
    DWORD dwResult = NetShareEnum(server, 1, &pBuf, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resume);

    if (dwResult == NERR_Success && pBuf != NULL)
    {
        for (DWORD i = 0; i < entriesRead; i++) {
            DWORD shareType = pBuf[i].shi1_type;
            wprintf(L"Share: %ls Remark: %ls Type: ", pBuf[i].shi1_netname, pBuf[i].shi1_remark);
            switch (shareType) {
            case STYPE_DISKTREE:
                wprintf(L"Disk Drive");
                break;
            case STYPE_PRINTQ:
                wprintf(L"Printer");
                break;
            case STYPE_DEVICE:
                wprintf(L"Communications ");
                break;
            case STYPE_IPC:
                wprintf(L"IPC ");
                break;
            default:
                wprintf(L"Unknown");
            }

            wprintf(L"\n");
        }

        NetApiBufferFree(pBuf);
    }
    else {
        wprintf(L"Error getting shares: %d \n", dwResult);
    }
}

BOOL EnumActiveLoginSessionsViaSMB(LPWSTR server)
{
    LPSESSION_INFO_0 pBuf = NULL;
    DWORD entriesRead = 0, totalEntries = 0, resume = 0;

    NET_API_STATUS status = NetSessionEnum(
        server,  // server name
        NULL,  // UncClientName required when targetting a specfic session - NULL enumerates all sessions
        L"b.jones",
        0,
        (LPBYTE*)&pBuf,
        MAX_PREFERRED_LENGTH,
        &entriesRead,
        &totalEntries,
        &resume
    );

    if (status == NERR_Success && pBuf != NULL) {
        for (DWORD i = 0; i < entriesRead; i++) {
            wprintf(L"Computer: %s\n",
                pBuf[i].sesi0_cname);
                //pBuf[i].sesi10_cname);
        }
        NetApiBufferFree(pBuf);
    }
    else {
        wprintf(L"Error: %lu\n", status);
        return FALSE;
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

//PWCHAR filter = L"(objectClass=computer)";
//PWCHAR attrs[] = { L"cn", L"dNSHostName", L"operatingSystem", L"operatingSystemVersion", L"lastLogonTimestamp", L"userAccountControl", NULL};

    //if (!EnumerateShares(DC))
    //{
    //    goto cleanup;
    //}

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
