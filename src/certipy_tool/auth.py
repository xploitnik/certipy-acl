# certipy_tool/auth.py
# -*- coding: utf-8 -*-
#
# Socket LDAP para Certipy-ACL:
#  - Soporta NTLM y Kerberos (GSSAPI)
#  - get_effective_control_entries(): devuelve [(dn, SR_SECURITY_DESCRIPTOR)]
#  - resolve_sid(sid): intenta resolver SIDs a nombre consultando objectSid (binario)
#
from typing import List, Tuple

from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, SASL, GSSAPI
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID


def domain_to_base_dn(domain: str) -> str:
    # "certified.htb" -> "DC=certified,DC=htb"
    parts = [p for p in domain.split(".") if p]
    return ",".join(f"DC={p}" for p in parts)


class LDAPSocket:
    def __init__(self, target: str, username: str, password: str,
                 domain: str, dc_ip: str, use_ldaps: bool = False,
                 auth_method: str = "ntlm", ccache: str = None,
                 dc_fqdn: str = None, starttls: bool = False):
        """
        target: host/IP al que conectarse
        username: UPN o sAMAccountName (solo NTLM)
        password: Contraseña (solo NTLM)
        domain: FQDN del dominio (p.ej. certified.htb)
        auth_method: "ntlm" o "kerberos"
        """
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.dc_ip = dc_ip
        self.use_ldaps = use_ldaps
        self.auth_method = auth_method
        self.ccache = ccache
        self.dc_fqdn = dc_fqdn
        self.starttls = starttls

        # ldap:// o ldaps://
        server = Server(self.target, use_ssl=self.use_ldaps, get_info=ALL)

        if self.auth_method == "ntlm":
            # Formato NTLM: DOMAIN\user
            user_part = username.split("@", 1)[0]
            ntlm_user = f"{self.domain.split('.')[0].upper()}\\{user_part}"

            self.conn = Connection(
                server,
                user=ntlm_user,
                password=self.password,
                authentication=NTLM,
                auto_bind=True,
            )

        elif self.auth_method == "kerberos":
            # Kerberos/GSSAPI usa ticket cache (kinit / impacket-getTGT)
            self.conn = Connection(
                server,
                authentication=SASL,
                sasl_mechanism=GSSAPI,
                auto_bind=True,
            )

        else:
            raise ValueError(f"Unsupported auth method: {self.auth_method}")

        self.base_dn = domain_to_base_dn(self.domain)
        print(f"[AUTH] LDAP bind successful via {self.auth_method.upper()}.")

    def get_effective_control_entries(self) -> List[Tuple[str, SR_SECURITY_DESCRIPTOR]]:
        """
        Devuelve lista de (DN, SR_SECURITY_DESCRIPTOR) para todo el bosque bajo base_dn.
        Solo pide la DACL (sdflags=0x04).
        """
        controls = security_descriptor_control(sdflags=0x04)
        print(f"[AUTH] Searching objects with ACLs for {self.username}@{self.domain}...")

        self.conn.search(
            search_base=self.base_dn,
            search_filter="(objectClass=*)",
            search_scope=SUBTREE,
            attributes=["nTSecurityDescriptor"],
            controls=controls,
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

    def resolve_sid(self, sid_str: str) -> str:
        """
        Intenta resolver un SID a sAMAccountName/CN buscando por objectSid binario.
        Si falla, devuelve el SID original.
        """
        try:
            sid_obj = LDAP_SID()
            sid_obj.fromCanonical(sid_str)
            sid_bytes = sid_obj.getData()

            hex_esc = "".join("\\{:02x}".format(b) for b in sid_bytes)
            flt = f"(objectSid={hex_esc})"

            self.conn.search(
                search_base=self.base_dn,
                search_filter=flt,
                search_scope=SUBTREE,
                attributes=["sAMAccountName", "cn", "distinguishedName"],
            )

            if not self.conn.entries:
                return sid_str

            e = self.conn.entries[0]
            for attr in ["sAMAccountName", "cn", "distinguishedName"]:
                try:
                    val = str(e[attr])
                    if val:
                        return val
                except Exception:
                    continue
            return sid_str
        except Exception:
            return sid_str



