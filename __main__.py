import argparse
from certipy_tool.auth import LDAPSocket
from certipy_tool.parse_acl import parse_acl_entries

# Global instance for resolving inside parse_acl
ldap_instance = None

def main():
    global ldap_instance

    parser = argparse.ArgumentParser(description="Certipy ACL Enumeration")
    parser.add_argument("-u", "--username", required=True, help="Username (e.g. user@domain.local)")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("-target", required=True, help="Target domain or IP")
    parser.add_argument("-dc-ip", required=True, help="Domain controller IP")
    parser.add_argument("--resolve-sids", action="store_true", help="Resolve SIDs to names")
    parser.add_argument("--only-users", action="store_true", help="Show only user objects")
    parser.add_argument("--filter-sid", help="Filter ACEs by this SID")

    args = parser.parse_args()

    ldap_instance = LDAPSocket(
        target=args.dc_ip,
        username=args.username,
        password=args.password,
        domain=args.target,
        dc_ip=args.dc_ip,
    )

    entries = ldap_instance.get_effective_control_entries()
    parse_acl_entries(
        entries,
        resolve=args.resolve_sids,
        only_users=args.only_users,
        sid_filter=args.filter_sid
    )

if __name__ == "__main__":
    main()

