
#include "AD_DS_defs.h"

// Used for querying domain controllers, domain join info, and memory management for NetAPI buffers. - Netapi32.dll
typedef struct {
    PFN_NetApiBufferFree NetApiBufferFree;
    PFN_DsGetDcSiteCoverageW DsGetDcSiteCoverageW;
    PFN_NetGetJoinInformation NetGetJoinInformation;
    PFN_NetGetJoinableOUs NetGetJoinableOUs;
    PFN_NetShareEnum NetShareEnum;
} NetApi32;


// Used for connecting to LDAP servers, performing searches, and working with LDAP messages. - wldap32.dll
typedef struct {
    PFN_ldap_initW ldap_initW;
    PFN_ldap_set_option ldap_set_option;
    PFN_ldap_bind_sW ldap_bind_sW;
    PFN_ldap_unbind ldap_unbind;
    PFN_ldap_search_sW ldap_search_sW;
    PFN_ldap_first_entry ldap_first_entry;
    PFN_ldap_first_attributeW ldap_first_attributeW;
    PFN_ldap_next_entry ldap_next_entry;
    PFN_ldap_get_values_lenW ldap_get_values_lenW;
    PFN_ldap_get_dnW ldap_get_dnW;
    PFN_ldap_value_free_len ldap_value_free_len;
    PFN_ldap_next_attributeW ldap_next_attributeW;
    PFN_ldap_msgfree ldap_msgfree;
    PFN_ldap_memfree ldap_memfree;
    PFN_ber_free ber_free; // Used for freeing BER elements (BerElement*) returned by some LDAP functions
} WLdap32;

typedef struct {
    wchar_t MachineName[MAX_PATH];  // the hostname of the local machine e.g. DESKTOP-43J4R
    wchar_t Username[MAX_PATH];     // the username of the current user e.g. j.smith
} Local;

typedef struct {
    wchar_t FQDN[MAX_PATH];     // FQDN = Fully Qaulified Domain Name - e.g. corp.local
    wchar_t TLD[MAX_PATH];      // TLD = Top Level Domain - e.g. .local
    wchar_t SLD[MAX_PATH];      // SLD = Second Level Domain - e.g. corp
    wchar_t DC[MAX_PATH];       // DC  = Domain Controller
} Domain;

typedef struct {
    LDAP* ld;       // LDAP session handle
    ULONG version;  // try to resolve this dynamically by probing the DC
    ULONG result;   // null this
} LDAPSession;

typedef struct {
    wchar_t base[MAX_PATH];             // base = DC=corp,DC=local
    wchar_t searchFilter[MAX_PATH];     // search objectClass type e.g. user, computer etc
    PWCHAR searchAttributes[MAX_PATH];  // search attributes e.g. memberOf
    LDAPMessage* response;              // holds the query response from the server
} LDAPQuery;