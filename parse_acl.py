from .auth import RIGHTS

def parse_acl_entries(entries, resolver=None, filter_sid=None):
    for dn, sd in entries:
        print(f"\n[ACL] {dn}")
        if not hasattr(sd, "dacl") or sd.dacl is None:
            print("  [!] No DACL or ACEs present")
            continue

        found = False

        for ace in sd.dacl.aces:
            try:
                sid = ace['Ace']['Sid'].formatCanonical()

                if filter_sid and sid != filter_sid:
                    continue  # Skip unrelated ACEs

                resolved_sid = resolver(sid) if resolver else sid
                mask = ace['Ace']['Mask']
                acetype = ace['AceType']

                typename = {
                    0x00: "ACCESS_ALLOWED",
                    0x01: "ACCESS_DENIED",
                    0x05: "ACCESS_ALLOWED_OBJECT_ACE_TYPE",
                    0x06: "ACCESS_DENIED_OBJECT_ACE_TYPE"
                }.get(acetype, f"UNKNOWN({acetype})")

                print(f"  🔐 ACE Summary:")
                print(f"  Field\t\tValue")
                print(f"  ACE Type\t{typename}")
                print(f"  SID\t\t{sid}")
                print(f"  Resolved SID\t{resolved_sid}")
                print(f"  Rights:")

                for bit, right in RIGHTS.items():
                    if mask & bit:
                        print(f"    ✅ {right}")

                found = True

            except Exception as e:
                print(f"  [!] Failed to parse ACE: {e}")

        if not found:
            print("  [!] No ACEs matched your SID.")

