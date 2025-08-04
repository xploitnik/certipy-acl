from ldap3 import Server, Connection, ALL, NTLM
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

class LDAPSocket:
    def __init__(self, target, username, password, domain, dc_ip, use_ldaps=False):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.dc_ip = dc_ip
        self.use_ldaps = use_ldaps
        self.user_sid = None

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

        self.user_sid = self.get_own_sid()
        print(f"[INFO] Current user SID: {self.user_sid}")

    def get_own_sid(self):
        self.conn.search(
            search_base="DC=" + ",DC=".join(self.domain.split(".")),
            search_filter=f"(sAMAccountName={self.username.split('@')[0]})",
            attributes=["objectSid"]
        )
        for entry in self.conn.entries:
            return entry["objectSid"].value
        return None

    def get_effective_control_entries(self):
        controls = security_descriptor_control(sdflags=0x04)

        print(f"[AUTH] Searching objects with ACLs for {self.username}@{self.domain}...")

        self.conn.search(
            search_base="DC=" + ",DC=".join(self.domain.split(".")),
            search_filter="(objectClass=*)",
            attributes=["nTSecurityDescriptor", "objectClass"],
            controls=controls
        )

        entries = []
        for entry in self.conn.entries:
            try:
                raw_sd = entry["nTSecurityDescriptor"].raw_values[0]
                sd = SR_SECURITY_DESCRIPTOR(raw_sd)
                dn = entry.entry_dn
                obj_classes = entry["objectClass"].values
                entries.append((dn, sd, obj_classes))
            except Exception:
                continue

        return entries

    def resolve_sid(self, sid):
        if sid.startswith("S-1-5-"):
            self.conn.search(
                search_base="DC=" + ",DC=".join(self.domain.split(".")),
                search_filter=f"(objectSid={sid})",
                attributes=["sAMAccountName"]
            )
            if self.conn.entries:
                return self.conn.entries[0]["sAMAccountName"].value
        return sid


