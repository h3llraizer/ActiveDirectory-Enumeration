#define PHNT_VERSION PHNT_WINDOWS_11
#include <phnt_windows.h>
#include <phnt.h>
#include <stdio.h>
#include "Parser.h"


BOOL GetVariableValueFromName(wchar_t*** envp, wchar_t* VariableName, wchar_t* Value)
{
    BOOL machineNameFound = FALSE;
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

        if (wcscmp(envVar, VariableName) == 0)
        {
            machineNameFound = TRUE;
            int dcLength = 0;
            for (int i = varLength + 1; (*env)[i] != L'\0'; i++)
            {
                Value[dcLength] = (*env)[i];
                dcLength++;
            }

            Value[dcLength + 1] = L'\0';

            return machineNameFound;
        }

    }

    return machineNameFound;
}

BOOL GetDomainName(wchar_t*** envp, wchar_t* FQDN, wchar_t* TLD, wchar_t* SLD)
{
    BOOL domainJoined = FALSE;

    if (GetVariableValueFromName(envp, L"USERDNSDOMAIN", FQDN))
    {
        int sldLength = 0;
        int tldLength = 0;
        for (int i = 0; FQDN[i] != L'\0'; i++)
        {
            if (FQDN[i] == L'.')
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

    return domainJoined;
}