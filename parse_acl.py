# certipy_tool/parse_acl.py
#!/usr/bin/env python3
from typing import Generator, Iterable, List, Optional, Tuple, Set

from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE,
    ACCESS_DENIED_ACE,
    ACCESS_MASK,
    ACE,
    LDAP_SID,
    SR_SECURITY_DESCRIPTOR,
)

# --- constants (unchanged) ---
DELETE = 0x00010000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
SYNCHRONIZE = 0x00100000

DS_CREATE_CHILD   = 0x00000001
DS_DELETE_CHILD   = 0x00000002
DS_LIST_CONTENTS  = 0x00000004
DS_SELF           = 0x00000008
DS_READ_PROP      = 0x00000010
DS_WRITE_PROP     = 0x00000020
DS_DELETE_TREE    = 0x00000040
DS_LIST_OBJECT    = 0x00000080
DS_CONTROL_ACCESS = 0x00000100

GENERIC_ALL     = 0x10000000
GENERIC_EXECUTE = 0x20000000
GENERIC_WRITE   = 0x40000000
GENERIC_READ    = 0x80000000


def _sid_bin_to_sddl(sid_bin: bytes) -> str:
    try:
        return LDAP_SID(data=sid_bin).formatCanonical()
    except Exception:
        return "<bad SID>"


def _mask_to_rights(mask_val: int) -> List[str]:
    r: List[str] = []
    if mask_val & GENERIC_ALL:     r.append("GenericAll")
    if mask_val & GENERIC_WRITE:   r.append("GenericWrite")
    if mask_val & GENERIC_READ:    r.append("GenericRead")
    if mask_val & GENERIC_EXECUTE: r.append("GenericExecute")

    if mask_val & WRITE_OWNER: r.append("WriteOwner")
    if mask_val & WRITE_DAC:   r.append("WriteDacl")
    if mask_val & DELETE:      r.append("Delete")
    if mask_val & READ_CONTROL:r.append("ReadControl")
    if mask_val & SYNCHRONIZE: r.append("Synchronize")

    if mask_val & DS_CREATE_CHILD:   r.append("CreateChild")
    if mask_val & DS_DELETE_CHILD:   r.append("DeleteChild")
    if mask_val & DS_LIST_CONTENTS:  r.append("ListContents")
    if mask_val & DS_SELF:           r.append("Self")
    if mask_val & DS_READ_PROP:      r.append("ReadProperty")
    if mask_val & DS_WRITE_PROP:     r.append("WriteProperty")
    if mask_val & DS_DELETE_TREE:    r.append("DeleteTree")
    if mask_val & DS_LIST_OBJECT:    r.append("ListObject")
    if mask_val & DS_CONTROL_ACCESS: r.append("ControlAccess")
    return r


def _ace_subject_sid(ace: ACE) -> Optional[bytes]:
    try:
        return bytes(ace["Sid"])
    except Exception:
        return None


def iter_acl_entries(
    sd_blob: bytes,
) -> Generator[Tuple[str, Optional[bytes], Optional[bytes], int], None, None]:
    sd = SR_SECURITY_DESCRIPTOR(data=sd_blob)
    try:
        dacl = sd["Dacl"]
    except Exception:
        dacl = None
    if not dacl:
        return

    try:
        aces = dacl.get("aces", None)
    except Exception:
        aces = None
    if not aces:
        return

    for ace in aces:
        if isinstance(ace, ACCESS_ALLOWED_ACE):
            ace_type = "ACCESS_ALLOWED"
        elif isinstance(ace, ACCESS_DENIED_ACE):
            ace_type = "ACCESS_DENIED"
        else:
            ace_type = str(ace.get("AceType", "ACE"))

        try:
            mask_val: int = int(ace["Mask"]) if isinstance(ace["Mask"], ACCESS_MASK) else int(ace["Mask"])
        except Exception:
            mask_val = 0

        obj_type_guid = None
        try:
            if "ObjectType" in ace and ace["ObjectType"] is not None:
                obj_type_guid = bytes(ace["ObjectType"])
        except Exception:
            obj_type_guid = None

        yield (ace_type, _ace_subject_sid(ace), obj_type_guid, mask_val)


def parse_acl_entries(
    sd_blob: bytes,
    resolve_sid_cb=None,
    filter_sid_bins: Optional[Iterable[bytes]] = None,
    filter_sid_sddls: Optional[Iterable[str]] = None,
    only_escalation: bool = False,
    debug_sids: bool = False,
) -> List[str]:
    lines: List[str] = []
    filter_bin_set: Set[bytes] = set(filter_sid_bins or [])
    filter_sddl_set: Set[str] = set(s.upper() for s in (filter_sid_sddls or []))

    for ace_type, sid_bin, obj_type_guid, mask_val in iter_acl_entries(sd_blob):
        if sid_bin is None:
            continue

        # Build the SDDL once
        sddl = _sid_bin_to_sddl(sid_bin)
        sddl_up = sddl.upper()

        # Apply filter if present (match by bytes OR by SDDL)
        if (filter_bin_set or filter_sddl_set) and (sid_bin not in filter_bin_set) and (sddl_up not in filter_sddl_set):
            continue

        rights = _mask_to_rights(mask_val)

        if only_escalation:
            if not (
                ("GenericAll" in rights)
                or ("GenericWrite" in rights)
                or ("WriteOwner" in rights)
                or ("WriteDacl" in rights)
                or ("CreateChild" in rights)
                or ("WriteProperty" in rights)
            ):
                continue

        subject = None
        if resolve_sid_cb:
            try:
                subject = resolve_sid_cb(sid_bin)
            except Exception:
                subject = None
        subject = subject or sddl

        rights_str = ", ".join(rights) if rights else "(no common rights)"
        sddl_line = f"\n    SID (SDDL):     {sddl}" if debug_sids else ""

        if obj_type_guid:
            line = (
                "  🔐 ACE Summary:\n"
                f"    ACE Type:       {ace_type}\n"
                f"    SID (bin):      {sid_bin!r}"
                f"{sddl_line}\n"
                f"    Resolved SID:   {subject}\n"
                f"    ObjectType:     {obj_type_guid!r}\n"
                "    Rights:\n"
                f"      ✅ {rights_str}"
            )
        else:
            line = (
                "  🔐 ACE Summary:\n"
                f"    ACE Type:       {ace_type}\n"
                f"    SID (bin):      {sid_bin!r}"
                f"{sddl_line}\n"
                f"    Resolved SID:   {subject}\n"
                "    Rights:\n"
                f"      ✅ {rights_str}"
            )
        lines.append(line)

    if not lines:
        lines.append("    [!] No matching rights found.")
    return lines



