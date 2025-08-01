
from ldap3 import Server, Connection, ALL, NTLM
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

RIGHTS = {
    0x00000001: "ReadProperty",
    0x00000002: "WriteProperty",
    0x00000004: "CreateChild",
    0x00000008: "DeleteChild",
    0x00000010: "ListChildren",
    0x00000020: "Self",
    0x00000040: "ReadControl",
    0x00000100: "Delete",
    0x00020000: "WriteDACL",
    0x00080000: "WriteOwner",
    0x01000000: "GenericRead",
    0x02000000: "GenericWrite",
    0x04000000: "GenericExecute",
    0x08000000: "GenericAll",
}

class LDAPSocket:
    def __init__(self, target, username, password, domain, dc_ip, use_ldaps=False):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.dc_ip = dc_ip
        self.use_ldaps = use_ldaps

        ldap_server = Server(self.target, get_info=ALL)
        formatted_user = f"{self.domain}\\{self.username.split('@')[0]}"

        self.conn = Connection(
            ldap_server,
            user=formatted_user,
            password=self.password,
            authentication=NTLM,
            auto_bind=True
        )

        print("[AUTH] LDAP bind successful.")

    def get_effective_control_entries(self):
        controls = security_descriptor_control(sdflags=0x04)

        print(f"[AUTH] Searching objects with ACLs for {self.username}@{self.domain}...")

        self.conn.search(
            search_base="DC={},DC={}".format(*self.domain.split(".")),
            search_filter="(objectClass=*)",
            attributes=["nTSecurityDescriptor"],
            controls=controls
        )

        entries = []
        for entry in self.conn.entries:
            try:
                raw_sd = entry["nTSecurityDescriptor"].raw_values[0]
                sd = SR_SECURITY_DESCRIPTOR(raw_sd)
                entries.append((entry.entry_dn, sd))
            except Exception:
                continue

        return entries

    def resolve_sid(self, sid):
        sid_filter = f"(objectSid={sid})"
        self.conn.search(
            search_base="DC={},DC={}".format(*self.domain.split(".")),
            search_filter=sid_filter,
            attributes=["sAMAccountName", "distinguishedName"]
        )
        if self.conn.entries:
            entry = self.conn.entries[0]
            return str(entry["sAMAccountName"] or entry["distinguishedName"])
        return sid  # fallback to raw SID
