# ActiveDirectory-Enumeration

This serves as, what I hope to be, a helpful template for others to clone and aid them in enumerating Active Directory from a domain'd machine.

By default, the code:
- loads required DLL's and resolve the exported functions for making LDAP queries.
- parse the process paramters block (envp) to find the values for COMPUTERNAME, USERNAME and USERDNSDOMAIN
- evaluate if the machine is domain joined. If it isn't, then it will return stating so
- given that the machine is domain joined, it will attempt to bind to the domain controller and populate the ld structure which then becomes a handle to issue queries
- if the bind is successful, the proceeding query functions are sent and output is displayed to the console