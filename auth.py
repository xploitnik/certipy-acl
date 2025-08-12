#!/usr/bin/env python3
r"""
auth.py — LDAP helper for certipy-acl
"""

from dataclasses import dataclass
from typing import Dict, Generator, Iterable, List, Optional, Tuple

from ldap3 import ALL, ALL_ATTRIBUTES, BASE, Connection, NTLM, Server, SUBTREE
from ldap3.core.results import RESULT_SUCCESS
from ldap3.protocol.microsoft import security_descriptor_control


@dataclass
class LDAPObject:
    dn: str
    object_class: List[str]
    name: str
    nt_security_descriptor: Optional[bytes]
    object_sid: Optional[bytes]


class LDAPSocket:
    """
    Thin convenience wrapper around ldap3 for:
      - binding with UPN or DOMAIN\\user
      - discovering defaultNamingContext
      - reading nTSecurityDescriptor (Owner + DACL)
      - resolving SIDs -> names
    """

    def __init__(
        self,
        username: str,
        password: str,
        target: str,
        dc_ip: Optional[str] = None,
        use_ssl: bool = False,
        port: Optional[int] = None,
        timeout: int = 10,
    ):
        self.username = username
        self.password = password
        self.target = target
        self.dc_ip = dc_ip or target
        self.use_ssl = use_ssl
        self.port = port or (636 if use_ssl else 389)
        self.timeout = timeout

        self.server = Server(
            self.dc_ip,
            get_info=ALL,
            use_ssl=self.use_ssl,
            port=self.port,
            connect_timeout=self.timeout,
        )
        self.conn: Optional[Connection] = None
        self.default_nc: Optional[str] = None

    # ------------------------------ binding ------------------------------

    def bind(self) -> None:
        """
        Bind with either SIMPLE (UPN) or NTLM (DOMAIN\\user).
        """
        if "@" in self.username:
            # UPN -> SIMPLE bind
            self.conn = Connection(
                self.server,
                user=self.username,
                password=self.password,
                authentication="SIMPLE",
                auto_bind=True,
            )
        else:
            # Expect DOMAIN\\user for NTLM
            self.conn = Connection(
                self.server,
                user=self.username,
                password=self.password,
                authentication=NTLM,
                auto_bind=True,
            )

        if not self.conn.bound:
            raise RuntimeError("LDAP bind failed")
        # discover defaultNamingContext
        self.conn.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["defaultNamingContext"],
        )
        if not self.conn.entries:
            raise RuntimeError("Could not read defaultNamingContext from rootDSE")
        self.default_nc = str(self.conn.entries[0]["defaultNamingContext"])

    # ------------------------------ queries ------------------------------

    def iter_domain_objects(
        self,
        attributes: Optional[Iterable[str]] = None,
        page_size: int = 500,
    ) -> Generator[LDAPObject, None, None]:
        """
        Iterate all objects in the defaultNamingContext and return the
        nTSecurityDescriptor (Owner + DACL).
        """
        if self.conn is None or self.default_nc is None:
            raise RuntimeError("Not bound")

        attrs = list(attributes or [])
        for need in ("nTSecurityDescriptor", "objectClass", "name", "objectSid"):
            if need not in attrs:
                attrs.append(need)

        # Ask AD to include SD (Owner + DACL). SACL requires SeSecurityPrivilege.
        sd_control = security_descriptor_control(sdflags=0x05)  # OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION

        cookie = None
        while True:
            self.conn.extend.standard.paged_search(
                search_base=self.default_nc,
                search_filter="(objectClass=*)",
                search_scope=SUBTREE,
                attributes=attrs,
                paged_size=page_size,
                paged_cookie=cookie,
                controls=sd_control,
            )
            # ldap3 stores last response in result
            for entry in self.conn.response or []:
                if entry.get("type") != "searchResEntry":
                    continue
                dn = entry["dn"]
                attrs_dict = entry.get("attributes", {})

                sd = attrs_dict.get("nTSecurityDescriptor")
                if isinstance(sd, list):
                    sd = sd[0]
                obj = LDAPObject(
                    dn=dn,
                    object_class=list(attrs_dict.get("objectClass", []) or []),
                    name=str(attrs_dict.get("name", "")),
                    nt_security_descriptor=sd if isinstance(sd, (bytes, bytearray)) else None,
                    object_sid=attrs_dict.get("objectSid"),
                )
                yield obj

            cookie = self.conn.result.get("controls", {}).get("1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")
            if not cookie:
                break

    # ------------------------------ SID resolution ------------------------------

    def resolve_sid(self, sid_bin: bytes) -> Optional[str]:
        """
        Resolve a binary SID to a 'DOMAIN\\samAccountName' if possible.
        Falls back to the object DN, or None if not found.
        """
        if self.conn is None or self.default_nc is None:
            raise RuntimeError("Not bound")

        # LDAP filter must escape bytes of objectSid
        sid_escaped = "".join(f"\\{b:02x}" for b in sid_bin)
        flt = f"(objectSid={sid_escaped})"
        self.conn.search(
            search_base=self.default_nc,
            search_filter=flt,
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "distinguishedName"],
        )
        if not self.conn.entries:
            return None

        entry = self.conn.entries[0]
        sam = str(entry["sAMAccountName"]) if "sAMAccountName" in entry else None
        dn = str(entry["distinguishedName"]) if "distinguishedName" in entry else None

        if sam:
            # figure out NETBIOS/short domain (best effort from default NC)
            short_dom = self._short_domain()
            return f"{short_dom}\\{sam}" if short_dom else sam
        return dn

    def _short_domain(self) -> Optional[str]:
        """Return the left-most DC as a reasonable short name."""
        if not self.default_nc:
            return None
        # e.g. DC=certified,DC=htb -> certified
        parts = [p for p in self.default_nc.split(",") if p.upper().startswith("DC=")]
        if not parts:
            return None
        return parts[0][3:]



