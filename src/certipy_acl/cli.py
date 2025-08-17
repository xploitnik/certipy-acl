import argparse
from .core.ldap_client import LdapClient
from .core.filters import RightsFilter

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="certipy-acl",
        description="Lightweight LDAP ACL mapper with real ACE parsing",
    )
    p.add_argument("-u", "--username", required=True, help="user@domain or DOMAIN\\user")
    p.add_argument("-p", "--password", required=True, help="Password")
    p.add_argument("-d", "--domain", required=True, help="FQDN domain (e.g., corp.local)")
    p.add_argument("--dc-ip", required=True, help="Domain Controller IP/host")
    p.add_argument("--ldaps", action="store_true", help="Use LDAPS (port 636)")
    p.add_argument("--filter-sid", help="Focus enumeration to a specific SID")
    p.add_argument("--target-dn", help="Limit search to this DN (e.g., CN=Users,DC=corp,DC=local)")
    p.add_argument("--size-limit", type=int, default=0, help="Max number of objects to fetch (0 = no limit)")
    p.add_argument("--resolve-sids", action="store_true", help="Resolve SIDs to names (placeholder hook)")
    p.add_argument("--only-escalation", action="store_true",
                   help="Show only key escalation rights (WriteOwner, WriteDACL, GenericAll, GenericWrite)")
    p.add_argument("--hits-only", action="store_true", help="Hide objects without matches")
    p.add_argument("--verbose", action="store_true", help="Verbose output")
    return p

def main():
    args = build_parser().parse_args()

    client = LdapClient(
        target=args.domain,
        dc_ip=args.dc_ip,
        username=args.username,
        password=args.password,
        domain=args.domain,
        use_ldaps=args.ldaps,
    )

    entries = client.get_effective_control_entries(base_dn=args.target_dn, size_limit=args.size_limit)

    rf = RightsFilter(only_escalation=args.only_escalation)
    matched = 0

    for dn, sd in entries:
        parsed = rf.parse_object(
            dn,
            sd,
            filter_sid=args.filter_sid,
            resolve_sid=args.resolve_sids,
            verbose=args.verbose,
        )
        if parsed["matched"]:
            matched += 1
            print(parsed["render"])
        else:
            if not args.hits_only:
                print(parsed["render"])

    if args.verbose:
        print(f"[INFO] Objects with matches: {matched} / {len(entries)}")
