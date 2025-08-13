import argparse
import sys
from certipy_tool.auth import LDAPSocket
from certipy_tool.parse_acl import parse_acl_entries

def build_parser():
    p = argparse.ArgumentParser(description="Certipy-ACL — LDAP ACL enumeration")
    p.add_argument("-u", "--username", required=True, help="UPN (e.g. user@domain.local)")
    p.add_argument("-p", "--password", required=True, help="Password")

    # Support old -target and new -d/--domain
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-target", help="AD domain (compat) e.g. certified.htb")
    g.add_argument("-d", "--domain", help="AD domain e.g. certified.htb")

    p.add_argument("--dc-ip", required=True, help="Domain Controller IP/host for LDAP")
    p.add_argument("--resolve-sids", action="store_true", help="Resolve SIDs to sAMAccountName")
    p.add_argument("--only-users", action="store_true", help="Show only user/person objects")
    p.add_argument("--filter-sid", help="Filter ACEs by this canonical SID (S-1-5-...)")
    return p

def main():
    args = build_parser().parse_args()
    domain = args.domain if args.domain else args.target

    ldap = LDAPSocket(
        target=args.dc_ip,
        username=args.username,
        password=args.password,
        domain=domain,
        dc_ip=args.dc_ip,
    )

    entries = ldap.get_effective_control_entries()
    parse_acl_entries(
        entries,
        resolve=args.resolve_sids,
        only_users=args.only_users,
        sid_filter=args.filter_sid,
        ldap=ldap,  # <-- important: pass LDAP instance for SID resolution
    )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)

