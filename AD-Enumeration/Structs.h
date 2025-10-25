
typedef struct Local {
    wchar_t MachineName[MAX_PATH];  // the hostname of the local machine e.g. DESKTOP-43J4R
    wchar_t Username[MAX_PATH];     // the username of the current user e.g. j.smith
};

typedef struct Domain {
    wchar_t FQDN[MAX_PATH];     // FQDN = Fully Qaulified Domain Name - e.g. corp.local
    wchar_t TLD[MAX_PATH];      // TLD = Top Level Domain - e.g. .local
    wchar_t SLD[MAX_PATH];      // SLD = Second Level Domain - e.g. corp
    wchar_t DC[MAX_PATH];       // DC  = Domain Controller
};

typedef struct LDAPSession {
    LDAP* ld;       // LDAP session handle
    ULONG version;  // try to resolve this dynamically by probing the DC
    ULONG result;   // null this
};

typedef struct LDAPQuery {
    wchar_t base[MAX_PATH];  // base = DC=corp,DC=local
    wchar_t searchFilter[MAX_PATH];   // search objectClass type e.g. user, computers etc
    PWCHAR searchAttributes[MAX_PATH];
    LDAPMessage* response;  // holds the query response from the server
};