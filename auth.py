from ldap3 import Server, Connection, ALL, NTLM
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID


class LDAPSocket:
    def __init__(self, target, username, password, domain, dc_ip, use_ldaps: bool = False):
        """
        target: DC host/IP for LDAP (usually same as dc_ip)
        username: UPN or user@domain
        domain: AD domain (e.g., certified.htb)
        dc_ip: domain controller IP (kept for compatibility)
        use_ldaps: set True for LDAPS (636)
        """
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.dc_ip = dc_ip
        self.use_ldaps = use_ldaps
        self.user_sid = None

        server = Server(self.target, get_info=ALL, use_ssl=bool(self.use_ldaps))

        # Escape the backslash in the domain\user string
        formatted_user = f"{self.domain}\\{self.username.split('@')[0]}"

        self.conn = Connection(
            server,
            user=formatted_user,
            password=self.password,
            authentication=NTLM,
            auto_bind=True,
        )
        print("[AUTH] LDAP bind successful.")

        self.user_sid = self.get_own_sid()
        print(f"[INFO] Current user SID: {self.user_sid}")

    @property
    def domain_dn(self) -> str:
        return "DC=" + ",DC=".join(self.domain.split("."))

    @property
    def upn(self) -> str:
        return self.username if "@" in self.username else f"{self.username}@{self.domain}"

    def get_own_sid(self):
        self.conn.search(
            search_base=self.domain_dn,
            search_filter=f"(sAMAccountName={self.username.split('@')[0]})",
            attributes=["objectSid"],
        )
        for entry in self.conn.entries:
            return entry["objectSid"].value
        return None

    def get_effective_control_entries(self):
        controls = security_descriptor_control(sdflags=0x07)
        print(f"[AUTH] Searching objects with ACLs for {self.upn}...")

        self.conn.search(
            search_base=self.domain_dn,
            search_filter="(objectClass=*)",
            attributes=["nTSecurityDescriptor", "objectClass"],
            controls=controls,
        )

        entries = []
        for entry in self.conn.entries:
            dn = entry.entry_dn
            try:
                if "nTSecurityDescriptor" not in entry or not entry["nTSecurityDescriptor"].raw_values:
                    continue

                raw_sd = entry["nTSecurityDescriptor"].raw_values[0]
                sd = SR_SECURITY_DESCRIPTOR()
                sd.fromString(raw_sd)

                obj_classes = entry["objectClass"].values if "objectClass" in entry else []
                entries.append((dn, sd, obj_classes))
            except Exception:
                continue

        return entries

    def resolve_sid(self, sid_str: str) -> str:
        try:
            ldap_sid = LDAP_SID()
            ldap_sid.fromCanonical(sid_str)
            sid_bytes = ldap_sid.getData()
            escaped = "".join(f"\\{b:02x}" for b in sid_bytes)

            self.conn.search(
                search_base=self.domain_dn,
                search_filter=f"(objectSid={escaped})",
                attributes=["sAMAccountName"],
            )
            if self.conn.entries:
                return self.conn.entries[0]["sAMAccountName"].value
        except Exception:
            pass
        return sid_str

