#ifndef AD_DS_DEFS_H
#define AD_DS_DEFS_H
#pragma once
#define PHNT_VERSION PHNT_WINDOWS_11
#include <phnt_windows.h>
#include <phnt.h>
#include <lm.h>
#include <stdio.h>
#include <winldap.h>
#include <wtsapi32.h>
#include <dsgetdc.h>
#include <winber.h>

typedef NET_API_STATUS (__stdcall* PFN_NetApiBufferFree)(
	LPVOID Buffer
);

typedef DWORD (__stdcall* PFN_DsGetDcSiteCoverageW)(
	LPCWSTR ServerName,
	PULONG  EntryCount,
	LPWSTR** SiteNames
);

typedef NET_API_STATUS (__stdcall* PFN_NetGetJoinInformation)(
	LPCWSTR lpServer,
	LPWSTR* lpNameBuffer,
	PNETSETUP_JOIN_STATUS BufferType
);

typedef NET_API_STATUS (__stdcall* PFN_NetGetJoinableOUs)(
	LPCWSTR lpServer,
	LPCWSTR lpDomain,
	LPCWSTR lpAccount,
	LPCWSTR lpPassword,
	DWORD* OUCount,
	LPWSTR** OUs
);

typedef LDAP* (__cdecl* PFN_ldap_initW)(
	const PWSTR HostName,
	ULONG       PortNumber
	);

typedef ULONG (__cdecl* PFN_ldap_set_option)(
	LDAP* ld,
	int        option,
	const void* invalue
);

typedef ULONG (__cdecl* PFN_ldap_bind_sW)(
	LDAP* ld,
	PWSTR  dn,
	PWCHAR cred,
	ULONG  method
);

typedef ULONG (__cdecl* PFN_ldap_unbind)(
	LDAP* ld
);

typedef ULONG (__cdecl* PFN_ldap_search_sW)(
	LDAP* ld,
	const PWSTR base,
	ULONG       scope,
	const PWSTR filter,
	PZPWSTR     attrs,
	ULONG       attrsonly,
	LDAPMessage** res
);

typedef LDAPMessage* (__cdecl* PFN_ldap_first_entry)(
	LDAP* ld,
	LDAPMessage* res
);

typedef PWCHAR (__cdecl* PFN_ldap_first_attributeW)(
	LDAP* ld,
	LDAPMessage* entry,
	BerElement** ptr
);

typedef BERVAL** (__cdecl* PFN_ldap_get_values_lenW)(
	LDAP* ExternalHandle,
	LDAPMessage* Message,
	const PWSTR attr
);

typedef PWCHAR(__cdecl* PFN_ldap_get_dnW)(
	LDAP* ld,
	LDAPMessage* entry
	);

typedef ULONG (__cdecl* PFN_ldap_value_free_len)(
	BERVAL** vals
);

typedef PWCHAR (__cdecl* PFN_ldap_next_attributeW)(
	LDAP* ld,
	LDAPMessage* entry,
	BerElement* ptr
);

typedef LDAPMessage* (__cdecl* PFN_ldap_next_entry)(
	LDAP* ld,
	LDAPMessage* entry
	);

typedef VOID (__cdecl* PFN_ber_free)(
	BerElement* pBerElement,
	INT        fbuf
);

typedef ULONG (__cdecl* PFN_ldap_msgfree)(
	LDAPMessage* res
);

typedef VOID (__cdecl* PFN_ldap_memfree)(
	PCHAR Block
);

typedef DWORD (__cdecl* PFN_NetShareEnum)(
	LMSTR   servername,
	DWORD   level,
	LPBYTE* bufptr,
	DWORD   prefmaxlen,
	LPDWORD entriesread,
	LPDWORD totalentries,
	LPDWORD resume_handle
);

#endif