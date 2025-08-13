#!/usr/bin/env python3
r"""
__main__.py — entrypoint for: python3 -m certipy_tool
"""

import argparse
import sys
from typing import Optional, Set

from ldap3 import BASE
from ldap3.protocol.microsoft import security_descriptor_control

from .auth import LDAPSocket
from . import parse_acl as pacl


def _parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="certipy_tool",
        description="Enumerate LDAP ACLs and print ACEs, optionally filtered by a SID and resolving SIDs.",
    )
    ap.add_argument("-u", "--username", required=True, help="UPN (user@domain) or DOMAIN\\user")
    ap.add_argument("-p", "--password", required=True)
    ap.add_argument("-target", "--target", dest="target", required=True, help="Domain FQDN (e.g., certified.htb)")
    ap.add_argument("--dc-ip", dest="dc_ip", required=False, help="Domain Controller IP")
    ap.add_argument("--use-ssl", action="store_true", default=False, help="Use LDAPS (636) instead of LDAP (389)")
    ap.add_argument("--filter-sid", dest="filter_sid", help="Only show ACEs for this SID (S-1-5-21-...)")
    ap.add_argument("--resolve-sids", dest="resolve_sids", action="store_true", default=False)
    ap.add_argument("--only-escalation", dest="only_escalation", action="store_true", default=False,
                    help="Filter to WriteOwner/WriteDACL/GenericAll/GenericWrite/CreateChild/WriteProperty")
    ap.add_argument("--include-token-groups", action="store_true", default=False,
                    help="Include the user's tokenGroups SIDs in the filter")
    ap.add_argument("--dn", dest="dn", help="Single DN to query instead of walking the entire domain")
    ap.add_argument("--debug-sids", dest="debug_sids", action="store_true", default=False,
                    help="Also print SDDL SID strings per ACE")
    return ap.parse_args()


# --- SID helpers ---

def sid_str_to_bin(sid: str) -> bytes:
    """
    Convert SDDL SID string -> binary.
    """
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


def _print_acl_for_sd(
    dn: str,
    sd_blob: bytes,
    resolve_cb,
    filter_sid_bin_set: Optional[Set[bytes]],
    filter_sid_sddl_set: Optional[Set[str]],
    only_escalation: bool,
    debug_sids: bool,
) -> bool:
    print(f"\n[ACL] {dn}")
    if not sd_blob:
        print("    [!] No DACL or ACEs present")
        return False

    lines = pacl.parse_acl_entries(
        sd_blob,
        resolve_sid_cb=resolve_cb,
        filter_sid_bins=filter_sid_bin_set,
        filter_sid_sddls=filter_sid_sddl_set,
        only_escalation=only_escalation,
        debug_sids=debug_sids,
    )

    shown = False
    for line in lines:
        shown = True
        print(line)
    if not shown:
        print("    [!] No matching rights found.")
    return shown


def main() -> None:
    args = _parse_args()

    print("[AUTH] Binding to LDAP...")
    ldap = LDAPSocket(
        username=args.username,
        password=args.password,
        target=args.target,
        dc_ip=args.dc_ip,
        use_ssl=args.use_ssl,
    )
    ldap.bind()
    print("[AUTH] LDAP bind successful.")

    resolve_cb = ldap.resolve_sid if args.resolve_sids else None

    # --- Build filter: both raw bytes and SDDL strings ---
    filter_sid_bin_set: Optional[Set[bytes]] = set()
    filter_sid_sddl_set: Optional[Set[str]] = set()
    if args.filter_sid:
        try:
            filter_sid_bin_set.add(sid_str_to_bin(args.filter_sid))
            filter_sid_sddl_set.add(args.filter_sid.upper())
        except Exception as e:
            print(f"[WARN] Could not parse --filter-sid: {e}")
    if args.include_token_groups:
        try:
            sids = ldap.get_token_group_sids(args.username)
            if sids:
                filter_sid_bin_set.update(sids)
                # also add their SDDL strings
                from impacket.ldap.ldaptypes import LDAP_SID
                for b in sids:
                    try:
                        filter_sid_sddl_set.add(LDAP_SID(data=b).formatCanonical().upper())
                    except Exception:
                        pass
                print(f"[INFO] Added {len(sids)} tokenGroups to SID filter.")
        except Exception as e:
            print(f"[WARN] Could not fetch tokenGroups: {e}")

    if filter_sid_bin_set is not None and len(filter_sid_bin_set) == 0:
        filter_sid_bin_set = None
    if filter_sid_sddl_set is not None and len(filter_sid_sddl_set) == 0:
        filter_sid_sddl_set = None

    print(f"[AUTH] Searching objects with ACLs for {args.username}...")

    # --- Single DN branch ---
    if args.dn:
        # Pull nTSecurityDescriptor (Owner + DACL)
        sd_control = security_descriptor_control(sdflags=0x05)
        ok = ldap.conn.search(
            search_base=args.dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["nTSecurityDescriptor", "name"],
            controls=sd_control,
        )
        if not ok or not ldap.conn.entries:
            print(f"[ERR] DN not found or no entries returned: {args.dn}")
            return

        entry = ldap.conn.entries[0]
        raw = getattr(entry, "entry_raw_attributes", {}) or {}
        sd_val = raw.get("nTSecurityDescriptor")
        sd_blob = LDAPSocket._take_sd_blob(sd_val)
        _print_acl_for_sd(
            args.dn,
            sd_blob,
            resolve_cb,
            filter_sid_bin_set,
            filter_sid_sddl_set,
            args.only_escalation,
            args.debug_sids,
        )
        return

    # --- Full domain walk ---
    found_any = False
    for dn, sd_blob in ldap.get_effective_control_entries():
        shown = _print_acl_for_sd(
            dn,
            sd_blob,
            resolve_cb,
            filter_sid_bin_set,
            filter_sid_sddl_set,
            args.only_escalation,
            args.debug_sids,
        )
        found_any = found_any or shown

    if not found_any:
        print("\n[INFO] No ACEs matched your filter.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
