# certipy_tool/parse_acl.py
# -*- coding: utf-8 -*-
from typing import Callable, Iterable, List, Optional, Tuple

try:
    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
except Exception:
    SR_SECURITY_DESCRIPTOR = object

# === DS rights ===
DS_RIGHTS = {
    0x00000001: "CreateChild",
    0x00000002: "DeleteChild",
    0x00000004: "ListChildren",
    0x00000008: "Self",
    0x00000010: "ReadProperty",
    0x00000020: "WriteProperty",
    0x00000040: "DeleteTree",
    0x00000080: "ListObject",
    0x00000100: "ControlAccess",
}
# === Standard rights ===
STANDARD_RIGHTS = {
    0x00010000: "Delete",
    0x00020000: "ReadControl",
    0x00040000: "WriteDACL",
    0x00080000: "WriteOwner",
    0x00100000: "Synchronize",
    0x01000000: "AccessSystemSecurity",
}
# === Generic rights ===
GENERIC_RIGHTS = {
    0x10000000: "GenericAll",
    0x20000000: "GenericExecute",
    0x40000000: "GenericWrite",
    0x80000000: "GenericRead",
}
RIGHTS = {**DS_RIGHTS, **STANDARD_RIGHTS, **GENERIC_RIGHTS}
ALL_RIGHTS_MASK = 0
for bit in RIGHTS:
    ALL_RIGHTS_MASK |= bit

ACE_TYPE_NAMES = {
    0x00: "ACCESS_ALLOWED",
    0x01: "ACCESS_DENIED",
    0x05: "ACCESS_ALLOWED_OBJECT",
    0x06: "ACCESS_DENIED_OBJECT",
}
SE_DACL_PRESENT = 0x0004


def _ace_type_name(t: int) -> str:
    return ACE_TYPE_NAMES.get(t, f"UNKNOWN({t})")


def _mask_to_int(mask_obj) -> int:
    """
    Convierte impacket.ACCESS_MASK a int de forma a prueba de versiones.
    """
    # 1) Si ya es int, va directo
    if isinstance(mask_obj, int):
        return mask_obj
    # 2) Algunos exponen .getValue() o .mask
    for attr in ("getValue", "mask"):
        try:
            val = getattr(mask_obj, attr)
            if callable(val):
                v = val()
                if isinstance(v, int):
                    return v
            elif isinstance(val, int):
                return val
        except Exception:
            pass
    # 3) Camino robusto: bytes crudos little-endian
    try:
        raw = mask_obj.getData()  # 4 bytes LE
        if isinstance(raw, (bytes, bytearray)) and len(raw) >= 4:
            return int.from_bytes(raw[:4], "little", signed=False)
    except Exception:
        pass
    # 4) Último recurso: repr/str no es fiable -> error claro
    raise TypeError(f"No pude convertir ACCESS_MASK a int: {type(mask_obj)}")


def _decode_rights(mask: int) -> List[str]:
    names = []
    for table in (DS_RIGHTS, STANDARD_RIGHTS, GENERIC_RIGHTS):
        for bit, name in table.items():
            if mask & bit:
                names.append(name)
    return names


def _key_rights(mask: int, bh_compat: bool = True) -> dict:
    has_write_owner = bool(mask & 0x00080000)
    has_write_dacl = bool(mask & 0x00040000)
    has_generic_all = bool(mask & 0x10000000)
    has_gw_direct = bool(mask & 0x40000000)
    has_writeprop = bool(mask & 0x00000020)
    has_self = bool(mask & 0x00000008)
    has_gw_derived = bh_compat and (has_writeprop or has_self)
    return {
        "WriteOwner": has_write_owner,
        "WriteDACL": has_write_dacl,
        "GenericAll": has_generic_all,
        "GenericWrite_direct": has_gw_direct,
        "GenericWrite_derived": has_gw_derived,
    }


def _format_bool(label: str, val: bool, alt: Optional[str] = None) -> str:
    return f"  - {label}: {('YES' if val else 'NO') if not alt else (alt if val else 'NO')}"


def _should_print_ace(mask: int, only_escalation: bool, bh_compat: bool) -> bool:
    if not only_escalation:
        return True
    kk = _key_rights(mask, bh_compat)
    return any(
        [
            kk["WriteOwner"],
            kk["WriteDACL"],
            kk["GenericAll"],
            kk["GenericWrite_direct"],
            kk["GenericWrite_derived"],
        ]
    )


def _resolve_sid_safe(sid: str, resolver: Optional[Callable[[str], str]]) -> str:
    if not resolver:
        return sid
    try:
        return resolver(sid) or sid
    except Exception:
        return sid


def _is_dn_under(dn: str, base_dn: str) -> bool:
    if not base_dn:
        return True
    dn_l, base_l = dn.lower(), base_dn.lower()
    return dn_l == base_l or dn_l.endswith("," + base_l)


def _get_dacl(sd) -> Optional[object]:
    # Impacket a veces expone 'Dacl' como key o 'dacl' como propiedad
    try:
        return sd["Dacl"]  # type: ignore[index]
    except Exception:
        try:
            return getattr(sd, "dacl", None)
        except Exception:
            return None


def parse_acl_entries(
    entries: Iterable[Tuple[str, SR_SECURITY_DESCRIPTOR]],
    filter_sid: Optional[str] = None,
    resolve_sid: Optional[Callable[[str], str]] = None,
    only_escalation: bool = False,
    bh_compat: bool = True,
) -> None:
    for dn, sd in entries:
        print(f"[ACL] {dn}")

        dacl = _get_dacl(sd)
        aces = getattr(dacl, "aces", None) if dacl is not None else None
        if not dacl or not aces:
            try:
                ctrl = getattr(sd, "Control", 0)
                present = bool(ctrl & SE_DACL_PRESENT)
                print(f"    [!] No DACL o no hay ACEs presentes (SE_DACL_PRESENT={present})")
            except Exception:
                print("    [!] No DACL o no hay ACEs presentes")
            continue

        printed = False
        for ace in aces:
            try:
                sid = ace["Ace"]["Sid"].formatCanonical()
                if filter_sid and sid != filter_sid:
                    continue

                mask = _mask_to_int(ace["Ace"]["Mask"])  # ← FIX principal
                acetype = ace["AceType"]

                if not _should_print_ace(mask, only_escalation, bh_compat):
                    continue

                printed = True
                rights = _decode_rights(mask)
                unknown_bits = mask & (~ALL_RIGHTS_MASK)

                print("  🔐 ACE Summary:")
                print(f"    ACE Type:       {_ace_type_name(acetype)}")
                print(f"    SID:            {sid}")
                resolved = _resolve_sid_safe(sid, resolve_sid)
                print(f"    Resolved SID:   {resolved}")
                print(f"    Mask (hex):     {hex(mask)}")
                print("    Rights:")
                if rights:
                    for r in rights:
                        print(f"      ✅ {r}")
                else:
                    print("      – (no se reconocieron derechos en esta máscara)")
                if unknown_bits:
                    print(f"      … Bits desconocidos: {hex(unknown_bits)}")

                kk = _key_rights(mask, bh_compat)
                print("    Key rights (quick check):")
                print(_format_bool("  WriteOwner", kk["WriteOwner"]))
                print(_format_bool("  WriteDACL", kk["WriteDACL"]))
                print(_format_bool("  GenericAll", kk["GenericAll"]))
                if kk["GenericWrite_direct"]:
                    print(_format_bool("  GenericWrite", True, "YES (direct)"))
                elif kk["GenericWrite_derived"]:
                    print(_format_bool("  GenericWrite", True, "YES (derived)"))
                else:
                    print(_format_bool("  GenericWrite", False))
                if (not kk["GenericWrite_direct"]) and kk["GenericWrite_derived"]:
                    print("    [i] GenericWrite (derived) inferido por WriteProperty/Self (compatibilidad BH).")
                print("")
            except Exception as e:
                print(f"    [!] Error al procesar ACE: {e}")

        if filter_sid and not printed:
            print(f"    [!] No hay ACEs que referencien SID {filter_sid} en este objeto.")
        elif not printed:
            print("    [!] No hay ACEs relevantes para mostrar con los filtros actuales.")


def enumerate_acls_for_sid(
    sock,
    filter_sid: Optional[str],
    target_dn: Optional[str] = None,
    resolve_sid: Optional[Callable[[str], str]] = None,
    only_escalation: bool = False,
    bh_compat: bool = True,
) -> None:
    entries = sock.get_effective_control_entries()
    if target_dn:
        entries = [(dn, sd) for dn, sd in entries if _is_dn_under(dn, target_dn)]
    parse_acl_entries(entries, filter_sid, resolve_sid, only_escalation, bh_compat)


def check_writeowner_for_dn(sock, target_dn: str, sid: str) -> bool:
    entries = sock.get_effective_control_entries()
    for dn, sd in entries:
        if dn.lower() != target_dn.lower():
            continue
        dacl = _get_dacl(sd)
        aces = getattr(dacl, "aces", None) if dacl else None
        if not aces:
            continue
        for ace in aces:
            try:
                if ace["Ace"]["Sid"].formatCanonical() != sid:
                    continue
                mask = _mask_to_int(ace["Ace"]["Mask"])
                has_wo = bool(mask & 0x00080000)
                print(f"[CHECK] {dn} — SID {sid} WriteOwner: {'YES' if has_wo else 'NO'} (mask={hex(mask)})")
                return has_wo
            except Exception:
                continue
    print(f"[CHECK] {target_dn} — no se encontró ACE para SID {sid}")
    return False


def decode_mask(mask: int) -> List[str]:
    return _decode_rights(mask)


def summarize_mask(mask: int, bh_compat: bool = True) -> dict:
    return _key_rights(mask, bh_compat)






