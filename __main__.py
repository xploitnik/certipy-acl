import argparse
from certipy_tool.auth import LDAPSocket
from certipy_tool.parse_acl import parse_acl_entries

def main():
    parser = argparse.ArgumentParser(description="Certipy ACL Viewer (Custom Fork)")
    parser.add_argument("action", choices=["acl"], help="Action to run")
    parser.add_argument("-u", "--username", required=True, help="Username (e.g. user@domain)")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("-target", "--target", required=True, help="Target hostname or IP")
    parser.add_argument("-dc-ip", "--dc_ip", required=True, help="Domain Controller IP")
    parser.add_argument("--resolve-sids", action="store_true", help="(Stub) Resolve SIDs to names")
    args = parser.parse_args()

    domain = args.username.split("@")[1]

    if args.action == "acl":
        ldap = LDAPSocket(
            target=args.target,
            username=args.username,
            password=args.password,
            domain=domain,
            dc_ip=args.dc_ip
        )
        entries = ldap.get_effective_control_entries()
        parse_acl_entries(entries)

if __name__ == "__main__":
    main()
