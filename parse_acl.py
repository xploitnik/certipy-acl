# parse_acl.py
from typing import Tuple, List, Optional, Set
import re
from ldap3 import BASE, Connection
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.core.exceptions import LDAPInvalidDnError
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACL as IMPACL

# ==== Constantes y mapeo genéricos ====
GENERIC_ALL     = 0x10000000
GENERIC_EXECUTE = 0x20000000
GENERIC_WRITE   = 0x40000000
GENERIC_READ    = 0x80000000

WRITE_OWNER       = 0x00080000
WRITE_DACL        = 0x00040000
DELETE            = 0x00010000
DS_CONTROL_ACCESS = 0x00000100
DS_WRITE_PROP     = 0x00000020
DS_READ_PROP      = 0x00000010

GENERIC_MAPPING_DS = {
    'GENERIC_READ':    0x00020000 | 0x00000010 | 0x00000001,
    'GENERIC_WRITE':   0x00000020 | 0x00000008 | 0x00000004,
    'GENERIC_EXECUTE': 0x00000040 | 0x00000080,
    'GENERIC_ALL':     0x00010000 | 0x00020000 | 0x00040000 | 0x00080000 |
                       0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 |
                       0x00000010 | 0x00000020 | 0x00000040 | 0x00000080 |
                       0x00000100
}

# ==== Utils máscaras / SD ====
def mask_to_int(m) -> int:
    if isinstance(m, int):
        return m
    for attr in ('mask', 'value', '_value', '_mask'):
        if hasattr(m, attr) and isinstance(getattr(m, attr), int):
            return getattr(m, attr)
    if hasattr(m, 'getData'):
        try:
            data = m.getData()
            if isinstance(data, (bytes, bytearray)) and len(data) >= 4:
                return int.from_bytes(data[:4], 'little')
        except Exception:
            pass
    s = repr(m)
    m2 = re.search(r'0x([0-9a-fA-F]+)', s)
    if m2:
        return int(m2.group(0), 16)
    raise TypeError(f"No pude convertir ACCESS_MASK a int: type={type(m)} repr={s}")

def expand_generic(mask: int) -> int:
    m = mask if isinstance(mask, int) else mask_to_int(mask)
    if m & GENERIC_ALL:     m |= GENERIC_MAPPING_DS['GENERIC_ALL']
    if m & GENERIC_WRITE:   m |= GENERIC_MAPPING_DS['GENERIC_WRITE']
    if m & GENERIC_READ:    m |= GENERIC_MAPPING_DS['GENERIC_READ']
    if m & GENERIC_EXECUTE: m |= GENERIC_MAPPING_DS['GENERIC_EXECUTE']
    return m & ~(GENERIC_ALL | GENERIC_WRITE | GENERIC_READ | GENERIC_EXECUTE)

def quick_rights(mask_any) -> dict:
    raw = mask_to_int(mask_any)
    exp = expand_generic(raw)
    known = WRITE_OWNER | WRITE_DACL | DELETE | DS_CONTROL_ACCESS | DS_WRITE_PROP | DS_READ_PROP
    return {
        'WriteOwner':     bool(exp & WRITE_OWNER),
        'WriteDACL':      bool(exp & WRITE_DACL),
        'GenericAll':     bool(raw & GENERIC_ALL),
        'GenericWrite':   bool(raw & GENERIC_WRITE),
        'GenericRead':    bool(raw & GENERIC_READ),
        'Delete':         bool(exp & DELETE),
        'ControlAccess':  bool(exp & DS_CONTROL_ACCESS),
        'WriteProperty':  bool(exp & DS_WRITE_PROP),
        'ReadProperty':   bool(exp & DS_READ_PROP),
        'raw':            raw,
        'expanded':       exp,
        'unknown_lowbits': exp & ~known
    }

def parse_sd_header(raw_sd: bytes):
    if len(raw_sd) < 20:
        return None, None, None, None, None
    control = int.from_bytes(raw_sd[2:4], 'little')
    owner_off = int.from_bytes(raw_sd[4:8], 'little')
    group_off = int.from_bytes(raw_sd[8:12], 'little')
    sacl_off  = int.from_bytes(raw_sd[12:16], 'little')
    dacl_off  = int.from_bytes(raw_sd[16:20], 'little')
    return control, owner_off, group_off, sacl_off, dacl_off

# ==== LDAP SD fetch (robusto a DN inválidos) ====
def fetch_sd_raw(conn: Connection, dn: str, sdflags: int) -> Optional[bytes]:
    # Validación ligera de DN
    if not isinstance(dn, str) or '=' not in dn:
        return None

    ctrl_obj = security_descriptor_control(sdflags=sdflags)
    controls = ctrl_obj if isinstance(ctrl_obj, list) else [
        (ctrl_obj.controlType, ctrl_obj.criticality, ctrl_obj.controlValue)
    ]

    try:
        ok = conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=['nTSecurityDescriptor'],
            controls=controls
        )
    except LDAPInvalidDnError:
        return None
    except Exception:
        return None

    if not ok or not conn.entries:
        return None

    e = conn.entries[0]
    if 'nTSecurityDescriptor' not in e or not hasattr(e['nTSecurityDescriptor'], 'raw_values') or not e['nTSecurityDescriptor'].raw_values:
        return None

    return e['nTSecurityDescriptor'].raw_values[0]

def safe_get_acetype(ace) -> int:
    try:
        if hasattr(ace, 'fields') and isinstance(ace.fields, dict) and 'AceType' in ace.fields:
            return int(ace.fields['AceType'])
    except Exception:
        pass
    try:
        return int(ace['AceType'])
    except Exception:
        pass
    try:
        return int(getattr(ace, 'AceType', 0))
    except Exception:
        return 0

# ==== Lógica principal ====
def check_writeowner_for_dn(conn: Connection, target_dn: str, eff_sids: Set[str], verbose: bool=False) -> Tuple[bool, List[str]]:
    msgs: List[str] = []
    # Intento OWNER|DACL
    raw_sd = fetch_sd_raw(conn, target_dn, 0x05)
    if not raw_sd:
        # Reintento DACL-only
        raw_sd = fetch_sd_raw(conn, target_dn, 0x04)
        if not raw_sd:
            msgs.append("[-] No se pudo obtener nTSecurityDescriptor (ni 0x05 ni 0x04).")
            return False, msgs
        msgs.append("[INFO] nTSecurityDescriptor size: {} bytes (sdflags=0x04)".format(len(raw_sd)))
    else:
        msgs.append("[INFO] nTSecurityDescriptor size: {} bytes (sdflags=0x05)".format(len(raw_sd)))

    ctrl, o_off, g_off, s_off, d_off = parse_sd_header(raw_sd)
    if ctrl is not None:
        msgs.append(f"[DEBUG] SD.Control=0x{ctrl:04x}  DaclOffset={d_off}")
    if not d_off:
        msgs.append("[-] DACL ausente en SD.")
        return False, msgs

    sd = SR_SECURITY_DESCRIPTOR(raw_sd)
    dacl = getattr(sd, 'Dacl', None)
    if (dacl is None or not getattr(dacl, 'aces', None)) and d_off:
        try:
            dacl = IMPACL(); dacl.fromString(raw_sd[d_off:])
        except Exception as ex:
            msgs.append(f"[DEBUG] Error parseando DACL manualmente: {ex}")

    if dacl is None or not getattr(dacl, 'aces', None):
        msgs.append("[-] DACL presente pero sin ACEs (o no se pudo parsear).")
        return False, msgs

    has_write_owner = False
    matched_aces = 0
    grant_detail = None

    for ace in dacl.aces:
        try:
            trustee = ace['Ace']['Sid'].formatCanonical()
        except Exception:
            continue
        if trustee not in eff_sids:
            continue
        matched_aces += 1
        raw_mask = mask_to_int(ace['Ace']['Mask'])
        exp_mask = expand_generic(raw_mask)
        if verbose:
            at = safe_get_acetype(ace)
            msgs.append(f"    [ACE] Trustee={trustee} AceType=0x{at:02x} MaskRaw=0x{raw_mask:08x} MaskExp=0x{exp_mask:08x}")
        if exp_mask & WRITE_OWNER:
            has_write_owner = True
            grant_detail = (trustee, raw_mask, exp_mask)

    msgs.append(f"[INFO] ACEs que aplican al token del usuario: {matched_aces}")
    if has_write_owner and grant_detail:
        t, mr, me = grant_detail
        msgs.append(f"[+] YES: WriteOwner sobre {target_dn} (concedido por {t}, MaskRaw=0x{mr:08x}, MaskExp=0x{me:08x})")
    else:
        msgs.append(f"[-] NO: WriteOwner sobre {target_dn}")
    return has_write_owner, msgs

def enumerate_acls_for_sid(conn: Connection, dns: List[str], filter_sid: str, resolve_sid_func, base_dn: str):
    for dn in dns:
        # Saltar DNs extraños/malformados
        if not isinstance(dn, str) or '=' not in dn:
            # print(f"\n[ACL] {dn}\n    [!] DN inválido, se omite.")
            continue

        try:
            raw_sd = fetch_sd_raw(conn, dn, 0x04)  # DACL only
        except LDAPInvalidDnError:
            # print(f"\n[ACL] {dn}\n    [!] DN inválido (LDAPInvalidDnError), se omite.")
            continue
        except Exception:
            # print(f"\n[ACL] {dn}\n    [!] Error inesperado al leer SD, se omite.")
            continue

        if not raw_sd:
            print(f"\n[ACL] {dn}\n    [!] No DACL or ACEs present")
            continue

        _, _, _, _, d_off = parse_sd_header(raw_sd)

        try:
            sd = SR_SECURITY_DESCRIPTOR(raw_sd)
            dacl = getattr(sd, 'Dacl', None)
            if (dacl is None or not getattr(dacl, 'aces', None)) and d_off:
                dacl = IMPACL(); dacl.fromString(raw_sd[d_off:])
        except Exception:
            dacl = None

        if dacl is None or not getattr(dacl, 'aces', None):
            print(f"\n[ACL] {dn}\n    [!] No ACEs referencing SID {filter_sid} on this object.\n    [!] No matching rights found.")
            continue

        matched = []
        for ace in dacl.aces:
            try:
                trustee = ace['Ace']['Sid'].formatCanonical()
            except Exception:
                continue
            if trustee == filter_sid:
                matched.append((ace, trustee))

        if not matched:
            print(f"\n[ACL] {dn}\n    [!] No ACEs referencing SID {filter_sid} on this object.\n    [!] No matching rights found.")
            continue

        for ace, trustee in matched:
            raw_mask = mask_to_int(ace['Ace']['Mask'])
            rights = quick_rights(raw_mask)
            try:
                at_val = int(ace.fields.get('AceType', 0)) if hasattr(ace, 'fields') else int(ace['AceType'])
            except Exception:
                at_val = 0
            ace_type = "ACCESS_ALLOWED" if at_val == 0x00 else ("ACCESS_DENIED" if at_val == 0x01 else f"0x{at_val:02x}")
            resolved = resolve_sid_func(conn, base_dn, trustee)

            print(f"\n[ACL] {dn}")
            print("  🔐 ACE Summary:")
            print(f"    ACE Type:       {ace_type}")
            print(f"    SID:            {trustee}")
            print(f"    Resolved SID:   {resolved}")
            print(f"    Mask (hex):     0x{rights['raw']:08x}")
            print("    Rights:")
            if rights['WriteProperty']: print("      ✅ WriteProperty")
            if rights['ControlAccess']: print("      ✅ ControlAccess")
            if rights['ReadProperty']:  print("      ✅ ReadProperty")
            if rights['unknown_lowbits']: print(f"      … Unknown bits: 0x{rights['unknown_lowbits']:08x}")
            print("    Key rights (quick check):")
            print(f"      - WriteOwner: {'YES' if rights['WriteOwner'] else 'NO'}")
            print(f"      - WriteDACL:  {'YES' if rights['WriteDACL'] else 'NO'}")
            print(f"      - GenericAll: {'YES' if rights['GenericAll'] else 'NO'}")
            print(f"      - GenericWrite:{'YES' if rights['GenericWrite'] else 'NO'}")
            print(f"      - GenericRead: {'YES' if rights['GenericRead'] else 'NO'}")
            print(f"      - Delete:     {'YES' if rights['Delete'] else 'NO'}")






