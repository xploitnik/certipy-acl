from .auth import RIGHTS

def parse_acl_entries(entries, resolver=None):
    for dn, sd in entries:
        print(f"\n[ACL] {dn}")
        if not hasattr(sd, "dacl") or sd.dacl is None:
            print("  [!] No DACL or ACEs present")
            continue

        for ace in sd.dacl.aces:
            try:
                sid = ace['Ace']['Sid'].formatCanonical()
                resolved_sid = resolver(sid) if resolver else sid
                mask = ace['Ace']['Mask']
                acetype = ace['AceType']

                typename = {
                    0x00: "ACCESS_ALLOWED",
                    0x01: "ACCESS_DENIED",
                    0x05: "ACCESS_ALLOWED_OBJECT_ACE_TYPE",
                    0x06: "ACCESS_DENIED_OBJECT_ACE_TYPE"
                }.get(acetype, f"UNKNOWN({acetype})")

                print(f"  [ACE] Type: {typename}")
                print(f"        SID: {resolved_sid}")
                print(f"        Mask: {hex(mask)}")

                for bit, right in RIGHTS.items():
                    if mask & bit:
                        print(f"        [+] {right}")

            except Exception as e:
                print(f"  [!] Failed to parse ACE: {e}")
