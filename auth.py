from typing import List, Set, Tuple, Optional
import struct
from ldap3 import Server, Connection, NTLM, SUBTREE, BASE

def build_base_dn(domain: str) -> str:
    return "DC=" + ",DC=".join(domain.split("."))

def ntlm_username(domain: str, username: str) -> str:
    # acepta UPN o DOMAIN\sam
    if "\\" in username:
        return username
    sam = username.split("@")[0]
    return f"{domain}\\{sam}"

def bind_ldap(dc_ip: str, domain: str, username: str, password: str) -> Connection:
    user_ntlm = ntlm_username(domain, username)
    server = Server(dc_ip, get_info=None)
    conn = Connection(server, user=user_ntlm, password=password, authentication=NTLM, auto_bind=True)
    return conn

# --- SID helpers ---
def bin_sid_to_str(bsid: bytes) -> str:
    if not bsid or len(bsid) < 8:
        return ""
    rev = bsid[0]
    cnt = bsid[1]
    auth = int.from_bytes(bsid[2:8], 'big')
    subs, off = [], 8
    for _ in range(cnt):
        subs.append(str(struct.unpack('<I', bsid[off:off+4])[0]))
        off += 4
    return f"S-{rev}-{auth}-" + "-".join(subs) if subs else f"S-{rev}-{auth}"

def sid_str_to_bin(sid: str) -> Optional[bytes]:
    # Convierte "S-1-5-21-..." a binario para comparar con objectSid
    try:
        parts = sid.strip().split('-')
        if parts[0] != 'S':
            return None
        rev = int(parts[1])
        ident_auth = int(parts[2])
        subauths = [int(x) for x in parts[3:]]
        b = bytearray()
        b.append(rev & 0xFF)
        b.append(len(subauths) & 0xFF)
        b.extend(ident_auth.to_bytes(6, 'big'))
        for sa in subauths:
            b.extend(sa.to_bytes(4, 'little', signed=False))
        return bytes(b)
    except Exception:
        return None

# --- Usuario y token ---
def get_user_dn_and_sid(conn: Connection, upn_or_sam: str, base_dn: str) -> Tuple[str, Optional[str]]:
    sam = upn_or_sam.split('@')[0]
    flt = f"(|(userPrincipalName={upn_or_sam})(sAMAccountName={sam}))"
    conn.search(base_dn, flt, attributes=['distinguishedName','objectSid'])
    if not conn.entries:
        raise RuntimeError(f"User not found: {upn_or_sam}")
    e = conn.entries[0]
    dn = str(e['distinguishedName'])
    sid = bin_sid_to_str(e['objectSid'].raw_values[0]) if e['objectSid'].raw_values else None
    return dn, sid

def get_effective_token_sids(conn: Connection, user_dn: str, self_sid: Optional[str]) -> Set[str]:
    eff: Set[str] = set([self_sid]) if self_sid else set()
    conn.search(user_dn, '(objectClass=*)', search_scope=BASE, attributes=['tokenGroups'])
    if conn.entries:
        entry = conn.entries[0]
        if 'tokenGroups' in entry and hasattr(entry['tokenGroups'], 'raw_values'):
            for raw in entry['tokenGroups'].raw_values:
                sid = bin_sid_to_str(raw)
                if sid:
                    eff.add(sid)
    return eff

def paged_search_dns(conn: Connection, base_dn: str, size_limit: int = 0) -> List[str]:
    dns: List[str] = []
    cookie = None
    while True:
        conn.search(
            search_base=base_dn,
            search_filter="(objectClass=*)",
            search_scope=SUBTREE,
            attributes=['distinguishedName'],
            paged_size=500,
            paged_cookie=cookie
        )
        for e in conn.entries:
            if 'distinguishedName' in e:
                dns.append(str(e['distinguishedName']))
        cookie = conn.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')
        if not cookie:
            break
        if size_limit and len(dns) >= size_limit:
            dns = dns[:size_limit]
            break
    return dns

def resolve_sid_name(conn: Connection, base_dn: str, sid_str: str) -> str:
    """
    Intenta resolver SID -> nombre (sAMAccountName o cn). Si falla, devuelve el SID.
    """
    sid_bin = sid_str_to_bin(sid_str)
    if not sid_bin:
        return sid_str
    flt = "(objectSid=" + sid_bin.decode('latin1') + ")"  # LDAP requiere bytes, ldap3 maneja raw internamente
    try:
        conn.search(base_dn, flt, attributes=['sAMAccountName', 'cn'])
        if conn.entries:
            e = conn.entries[0]
            if 'sAMAccountName' in e and str(e['sAMAccountName']):
                return str(e['sAMAccountName'])
            if 'cn' in e and str(e['cn']):
                return str(e['cn'])
    except Exception:
        pass
    return sid_str


