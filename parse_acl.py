#!/usr/bin/env python3
r"""
parse_acl.py — Parse SD DACL entries and pretty-print rights.
Uses impacket.ldap.ldaptypes for reliable parsing.

Fixes:
- Cast ACCESS_MASK -> int before bit ops to avoid: TypeError: 'ACCESS_MASK' & int
"""

from typing import Generator, Iterable, List, Optional, Tuple

from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE,
    ACCESS_DENIED_ACE,
    ACCESS_MASK,
    ACE,
    LDAP_SID,
    SR_SECURITY_DESCRIPTOR,
)
from impacket.uuid import string_to_bin


# ------------------------------ helpers ------------------------------

def _mask_to_rights(mask_val: int) -> List[str]:
    """
    Map common directory rights flags to human labels.
    Note: This is not exhaustive but covers the typical escalation bits.
    """
    RIGHTS = []
    # Generic rights
    if mask_val & 0x10000: RIGHTS.append("Delete")              # DELETE
    if mask_val & 0x20000: RIGHTS.append("ReadControl")         # READ_CONTROL
    if mask_val & 0x40000: RIGHTS.append("WriteDacl")           # WRITE_DAC
    if mask_val & 0x80000: RIGHTS.append("WriteOwner")          # WRITE_OWNER
    if mask_val & 0x100000: RIGHTS.append("Synchronize")        # SYNCHRONIZE

    # DS-specific (from MS-ADTS): Create/Delete Child, List, Self, Read/Write property
    if mask_val & 0x1: RIGHTS.append("ReadProperty")
    if mask_val & 0x2: RIGHTS.append("WriteProperty")
    if mask_val & 0x4: RIGHTS.append("CreateChild")
    if mask_val & 0x8: RIGHTS.append("DeleteChild")
    if mask_val & 0x10: RIGHTS.append("ListContents")
    if mask_val & 0x20: RIGHTS.append("Self")
    if mask_val & 0x40: RIGHTS.append("ReadControl (Obj)")  # rarely used
    if mask_val & 0x80: RIGHTS.append("WriteDacl (Obj)")    # rarely used

    # Extended rights (a few common ones show up via objectType, not the mask)
    return RIGHTS


def _ace_subject_sid(ace: ACE) -> Optional[bytes]:
    try:
        return bytes(ace["Sid"])
    except Exception:
        return None


def iter_acl_entries(
    sd_blob: bytes,
) -> Generator[Tuple[str, Optional[bytes], Optional[bytes], int], None, None]:
    """
    Yield (ace_type, subject_sid_bin, object_type_guid_bin, mask_val_int) for each ACE.
    object_type_guid_bin is meaningful when the ACE is object-specific.
    """
    sd = SR_SECURITY_DESCRIPTOR(data=sd_blob)
    if not sd or not sd["Dacl"] or not sd["Dacl"]["aces"]:
        return

    for ace in sd["Dacl"]["aces"]:
        if isinstance(ace, ACCESS_ALLOWED_ACE):
            ace_type = "ACCESS_ALLOWED"
        elif isinstance(ace, ACCESS_DENIED_ACE):
            ace_type = "ACCESS_DENIED"
        else:
            # other ACE classes are rare; skip for brevity
            ace_type = ace["AceType"]

        # Convert ACCESS_MASK to int before bit operations
        mask_val: int = int(ace["Mask"]) if isinstance(ace["Mask"], ACCESS_MASK) else int(ace["Mask"])

        obj_type_guid = None
        try:
            # Some ACEs are object-specific and include ObjectType (GUID)
            if "ObjectType" in ace and ace["ObjectType"] is not None:
                obj_type_guid = bytes(ace["ObjectType"])
        except Exception:
            obj_type_guid = None

        yield (ace_type, _ace_subject_sid(ace), obj_type_guid, mask_val)


def parse_acl_entries(
    sd_blob: bytes,
    resolve_sid_cb=None,
    filter_sid_bin: Optional[bytes] = None,
) -> List[str]:
    """
    Return pretty strings describing relevant ACEs.
    - resolve_sid_cb: callable(sid_bin)->str   (optional)
    - filter_sid_bin: if provided, only ACEs for this SID are returned
    """
    lines: List[str] = []

    for ace_type, sid_bin, obj_type_guid, mask_val in iter_acl_entries(sd_blob):
        if sid_bin is None:
            continue
        if filter_sid_bin and sid_bin != filter_sid_bin:
            continue

        subject = None
        if resolve_sid_cb:
            try:
                subject = resolve_sid_cb(sid_bin)
            except Exception:
                subject = None
        subject = subject or "<unresolved SID>"

        rights = _mask_to_rights(mask_val)
        rights_str = ", ".join(rights) if rights else "(no common rights)"

        if obj_type_guid:
            line = f"  🔐 ACE Summary:\n    ACE Type:       {ace_type}\n    SID:            {sid_bin!r}\n    Resolved SID:   {subject}\n    ObjectType:     {obj_type_guid!r}\n    Rights:\n      ✅ {rights_str}"
        else:
            line = f"  🔐 ACE Summary:\n    ACE Type:       {ace_type}\n    SID:            {sid_bin!r}\n    Resolved SID:   {subject}\n    Rights:\n      ✅ {rights_str}"

        lines.append(line)

    if not lines:
        lines.append("    [!] No matching rights found.")
    return lines



