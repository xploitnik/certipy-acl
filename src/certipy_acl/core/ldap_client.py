from ldap3 import Server, Connection, ALL, NTLM
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

class LdapClient:
    """
    Minimal LDAP wrapper to fetch nTSecurityDescriptor (DACLs).
    """

    def __init__(self, target, dc_ip, username, password, domain, use_ldaps=False):
        self.target = target
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
        self.domain = domain
        self.use_ldaps = use_ldaps

        server = Server(self.dc_ip, get_info=ALL, use_ssl=self.use_ldaps)
        formatted = f"{self.domain}\\{self.username.split('@')[0]}"

        print("[AUTH] Binding to LDAP...")
        self.conn = Connection(
            server,
            user=formatted,
            password=self.password,
            authentication=NTLM,
            auto_bind=True,
        )
        print("[AUTH] LDAP bind successful.")

    def get_effective_control_entries(self, base_dn=None, size_limit=0):
        """
        Returns a list of (dn, SR_SECURITY_DESCRIPTOR).
        Uses sdflags=0x04 to fetch only the DACL.
        """
        if base_dn is None:
            dom_parts = self.domain.split(".")
            base_dn = "DC=" + ",DC=".join(dom_parts)

        controls = security_descriptor_control(sdflags=0x04)  # DACL only
        print(f"[AUTH] Searching objects with ACLs for {self.username}@{self.domain}...")

        self.conn.search(
            search_base=base_dn,
            search_filter="(objectClass=*)",
            attributes=["nTSecurityDescriptor"],
            controls=controls,
            paged_size=500,
        )

        entries = []
        count = 0
        for e in self.conn.entries:
            try:
                raw = e["nTSecurityDescriptor"].raw_values[0]
                sd = SR_SECURITY_DESCRIPTOR(raw)
                entries.append((e.entry_dn, sd))
                count += 1
                if size_limit and count >= size_limit:
                    break
            except Exception:
                # Skip objects without a readable DACL
                continue
        return entries
