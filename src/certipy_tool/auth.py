# certipy_tool/auth.py
# -*- coding: utf-8 -*-
#
# Socket LDAP mínimo para Certipy-ACL:
#  - Bind NTLM (domain\username) a ldap:// o ldaps://
#  - get_effective_control_entries(): devuelve [(dn, SR_SECURITY_DESCRIPTOR)]
#  - resolve_sid(sid): intenta resolver SIDs a nombre consultando objectSid (binario)
#
from typing import List, Tuple

from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID


def domain_to_base_dn(domain: str) -> str:
    # "certified.htb" -> "DC=certified,DC=htb"
    parts = [p for p in domain.split(".") if p]
    return ",".join(f"DC={p}" for p in parts)


class LDAPSocket:
    def __init__(self, target: str, username: str, password: str,
                 domain: str, dc_ip: str, use_ldaps: bool = False):
        """
        target: host/IP al que conectarse (usa dc_ip para evitar DNS)
        username: UPN o sAMAccountName
        domain: FQDN del dominio (p.ej. certified.htb)
        """
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.dc_ip = dc_ip
        self.use_ldaps = use_ldaps

        # Server (ldap:// o ldaps://) — ldap3 controla use_ssl
        server = Server(self.target, use_ssl=self.use_ldaps, get_info=ALL)

        # Formato NTLM: DOMAIN\user
        user_part = username.split("@", 1)[0]
        ntlm_user = f"{self.domain.split('.')[0].upper()}\\{user_part}"

        # Bind
        self.conn = Connection(
            server,
            user=ntlm_user,
            password=self.password,
            authentication=NTLM,
            auto_bind=True,
        )

        self.base_dn = domain_to_base_dn(self.domain)
        print("[AUTH] LDAP bind successful.")

    def get_effective_control_entries(self) -> List[Tuple[str, SR_SECURITY_DESCRIPTOR]]:
        """
        Devuelve lista de (DN, SR_SECURITY_DESCRIPTOR) para todo el bosque bajo base_dn.
        Sólo pide la DACL (sdflags=0x04) para rendimiento.
        """
        controls = security_descriptor_control(sdflags=0x04)  # DACL only
        print(f"[AUTH] Searching objects with ACLs for {self.username}@{self.domain}...")

        # Nota: scope SUBTREE para todo el dominio
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
                # sin SD o no decodificable
                continue

        return entries

    def resolve_sid(self, sid_str: str) -> str:
        """
        Intenta resolver un SID a sAMAccountName/CN buscando por objectSid binario.
        Si falla, devuelve el SID original.
        """
        try:
            # Convertir SDDL a bytes (binario) con impacket
            sid_obj = LDAP_SID()
            sid_obj.fromCanonical(sid_str)
            sid_bytes = sid_obj.getData()

            # Armar filtro LDAP con bytes escapados (\XX)
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
            # Prioridad a sAMAccountName, luego CN
            name = None
            try:
                name = str(e["sAMAccountName"])
            except Exception:
                pass
            if not name:
                try:
                    name = str(e["cn"])
                except Exception:
                    pass
            if not name:
                # Último recurso: DN
                try:
                    name = str(e["distinguishedName"])
                except Exception:
                    pass
            return name or sid_str
        except Exception:
            return sid_str



