#!/usr/bin/env python3
r"""
auth.py — LDAP helper for certipy-acl
"""

from dataclasses import dataclass
from typing import Generator, Iterable, List, Optional, Tuple, Union

from ldap3 import ALL, BASE, Connection, NTLM, Server, SUBTREE
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
      - discovering base DN (defaultNamingContext / namingContexts from RootDSE)
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
        Bind con UPN (SIMPLE) o DOMAIN\\user (NTLM) y descubre el base DN.
        Pide atributos normales (*) y operacionales (+) del RootDSE para
        evitar 'invalid attribute type defaultNamingContext' en algunos servidores.
        """
        if "@" in self.username:
            # UPN -> SIMPLE
            self.conn = Connection(
                self.server,
                user=self.username,
                password=self.password,
                authentication="SIMPLE",
                auto_bind=True,
            )
        else:
            # DOMAIN\\user -> NTLM
            self.conn = Connection(
                self.server,
                user=self.username,
                password=self.password,
                authentication=NTLM,
                auto_bind=True,
            )

        if not self.conn.bound:
            raise RuntimeError("LDAP bind failed")

        # RootDSE: pedir '*' y '+' para traer todo lo normal + operacional
        self.conn.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["*", "+"],
        )
        if not self.conn.entries:
            raise RuntimeError("No RootDSE entries returned")

        root = self.conn.entries[0]
        attrs = root.entry_attributes_as_dict  # dict con todos los atributos
        default_nc = attrs.get("defaultNamingContext")
        if default_nc:
            if isinstance(default_nc, list):
                default_nc = default_nc[0]
            self.default_nc = str(default_nc)
        else:
            # Fallback a namingContexts
            ncs = attrs.get("namingContexts", [])
            if not isinstance(ncs, list):
                ncs = [ncs] if ncs else []
            ncs = [str(x) for x in ncs]
            dc_like = [x for x in ncs if x.upper().startswith("DC=")]
            self.default_nc = dc_like[0] if dc_like else (ncs[0] if ncs else None)

        if not self.default_nc:
            raise RuntimeError("Could not determine default naming context from RootDSE")

    # ------------------------------ helpers internos ------------------------------

    @staticmethod
    def _take_sd_blob(val) -> Optional[bytes]:
        """
        Devuelve el primer blob bytes válido de nTSecurityDescriptor,
        o None si no hay datos (maneja bytes, lista vacía, etc.).
        """
        if isinstance(val, (bytes, bytearray)):
            return val
        if isinstance(val, list):
            for v in val:
                if isinstance(v, (bytes, bytearray)):
                    return v
            return None
        return None

    # ------------------------------ queries ------------------------------

    def iter_domain_objects(
        self,
        attributes: Optional[Iterable[str]] = None,
        page_size: int = 500,
    ) -> Generator[LDAPObject, None, None]:
        """
        Itera todos los objetos en el defaultNamingContext y devuelve
        nTSecurityDescriptor (Owner + DACL) usando paginación nativa de ldap3.
        """
        if self.conn is None or self.default_nc is None:
            raise RuntimeError("Not bound")

        attrs = list(attributes or [])
        for need in ("nTSecurityDescriptor", "objectClass", "name", "objectSid"):
            if need not in attrs:
                attrs.append(need)

        # OWNER_SECURITY_INFORMATION (0x01) | DACL_SECURITY_INFORMATION (0x04) = 0x05
        sd_control = security_descriptor_control(sdflags=0x05)

        # ldap3 se encarga de la paginación si usamos generator=True
        results = self.conn.extend.standard.paged_search(
            search_base=self.default_nc,
            search_filter="(objectClass=*)",
            search_scope=SUBTREE,
            attributes=attrs,
            paged_size=page_size,
            generator=True,
            controls=sd_control,
        )

        for entry in results:
            if entry.get("type") != "searchResEntry":
                continue
            dn = entry["dn"]
            attrs_dict = entry.get("attributes", {}) or {}

            sd = self._take_sd_blob(attrs_dict.get("nTSecurityDescriptor"))

            yield LDAPObject(
                dn=dn,
                object_class=list(attrs_dict.get("objectClass", []) or []),
                name=str(attrs_dict.get("name", "")),
                nt_security_descriptor=sd,
                object_sid=attrs_dict.get("objectSid"),
            )

    # ------------------------------ SID resolution ------------------------------

    def _sid_str_to_bin(self, sid: str) -> bytes:
        import struct
        parts = sid.split("-")
        if parts[0] != "S":
            raise ValueError("Invalid SID")
        revision = int(parts[1])
        ident_auth = int(parts[2])
        subs = list(map(int, parts[3:]))
        subcount = len(subs)
        out = struct.pack("<BB", revision, subcount)
        out += ident_auth.to_bytes(6, byteorder="big")
        for s in subs:
            out += struct.pack("<I", s)
        return out

    def resolve_sid(self, sid_bin_or_str: Union[bytes, str]) -> Optional[str]:
        """
        Resuelve un SID (bytes o SDDL string) a 'DOMAIN\\samAccountName' si es posible.
        Si no, devuelve el DN; si no se encuentra, None.
        """
        if self.conn is None or self.default_nc is None:
            raise RuntimeError("Not bound")

        if isinstance(sid_bin_or_str, str):
            sid_bin = self._sid_str_to_bin(sid_bin_or_str)
        else:
            sid_bin = sid_bin_or_str

        # Escapar bytes de objectSid en el filtro LDAP
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
            short_dom = self._short_domain()
            return f"{short_dom}\\{sam}" if short_dom else sam
        return dn

    def _short_domain(self) -> Optional[str]:
        """Devuelve el primer DC= como nombre corto razonable."""
        if not self.default_nc:
            return None
        parts = [p for p in self.default_nc.split(",") if p.upper().startswith("DC=")]
        if not parts:
            return None
        return parts[0][3:]

    # ------------------------------ token groups (effective SIDs) ------------------------------

    def get_token_group_sids(self, upn_or_sam: str) -> List[bytes]:
        """
        Returns [objectSid] + tokenGroups (all as bytes) for the given principal.
        Accepts UPN (user@domain) or sAMAccountName.
        """
        if self.conn is None or self.default_nc is None:
            raise RuntimeError("Not bound")

        if "@" in upn_or_sam:
            flt = f"(|(userPrincipalName={upn_or_sam})(sAMAccountName={upn_or_sam.split('@',1)[0]}))"
        else:
            flt = f"(sAMAccountName={upn_or_sam})"

        self.conn.search(
            search_base=self.default_nc,
            search_filter=flt,
            search_scope=SUBTREE,
            attributes=["objectSid", "tokenGroups"],
        )
        if not self.conn.entries:
            return []

        e = self.conn.entries[0]
        out: List[bytes] = []

        try:
            sid = e["objectSid"].raw_values[0]
            if isinstance(sid, (bytes, bytearray)):
                out.append(bytes(sid))
        except Exception:
            pass

        try:
            for tg in e["tokenGroups"].raw_values:
                if isinstance(tg, (bytes, bytearray)):
                    out.append(bytes(tg))
        except Exception:
            pass

        return out

    # ------------------------------ compat shim ------------------------------

    def get_effective_control_entries(self) -> Generator[Tuple[str, Optional[bytes]], None, None]:
        """
        Compat: devuelve (dn, sd_blob) como lo espera el parser.
        """
        for obj in self.iter_domain_objects():
            yield (obj.dn, obj.nt_security_descriptor)
