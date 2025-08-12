#!/usr/bin/env python3
r"""
__main__.py — entrypoint for: python3 -m certipy_tool
"""

import argparse
import sys
from typing import Optional

from .auth import LDAPSocket
from .parse_acl import parse_acl_entries


def _parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="certipy_tool",
        description="Enumerate LDAP ACLs and print ACEs, optionally filtered by a SID and resolving SIDs.",
    )
    ap.add_argument("-u", "--username", required=True, help="UPN (user@domain) or DOMAIN\\user")
    ap.add_argument("-p", "--password", required=True)
    ap.add_argument("-target", "--target", dest="target", required=True, help="Domain FQDN (e.g., certified.htb)")
    ap.add_argument("--dc-ip", dest="dc_ip", required=False, help="Domain Controller IP")
    ap.add_argument("--use-ssl", action="store_true", default=False)
    ap.add_argument("--filter-sid", dest="filter_sid", help="Only show ACEs for this SID (e.g., S-1-5-21-...)")
    ap.add_argument("--resolve-sids", dest="resolve_sids", action="store_true", default=False)
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

    if args.resolve_sids:
        print("[INFO] SID resolution is enabled.")
        resolve_cb = ldap.resolve_sid
    else:
        resolve_cb = None

    filter_sid_bin: Optional[bytes] = None
    if args.filter_sid:
        try:
            filter_sid_bin = sid_str_to_bin(args.filter_sid)
        except Exception as e:
            print(f"[WARN] Could not parse --filter-sid: {e}")

    # We will iterate all objects in the domain NC and print ACEs for each
    print(f"[AUTH] Searching objects with ACLs for {args.username}...")
    found_any = False
    for obj in ldap.iter_domain_objects():
        dn = obj.dn
        print(f"\n[ACL] {dn}")
        sd = obj.nt_security_descriptor
        if not sd:
            print("    [!] No DACL or ACEs present")
            continue

        lines = parse_acl_entries(sd, resolve_sid_cb=resolve_cb, filter_sid_bin=filter_sid_bin)
        if lines:
            found_any = True
            for line in lines:
                print(line)
        else:
            print("    [!] No matching rights found.")

    if not found_any:
        print("\n[INFO] No ACEs matched your filter.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)

