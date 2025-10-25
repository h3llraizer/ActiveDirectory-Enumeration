#pragma once
#ifndef PARSER_H
#define PARSER_H

BOOL GetVariableValueFromName(wchar_t*** envp, wchar_t* VariableName, wchar_t* Value);
BOOL GetDomainName(wchar_t*** envp, wchar_t* FQDN, wchar_t* TLD, wchar_t* SLD);
BOOL GetDomainController(wchar_t*** envp, wchar_t* DC);

#endif
