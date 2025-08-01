from certipy_tool.auth import RIGHTS

# Define the escalation rights to filter for
ESCALATION_RIGHTS = {
    0x00080000,  # WriteOwner
    0x00020000,  # WriteDACL
    0x08000000,  # GenericAll
    0x02000000,  # GenericWrite
}

def parse_acl_entries(entries):
    for dn, sd in entries:
        print(f"[ACL] {dn}")
        if not hasattr(sd, "dacl") or sd.dacl is None:
            print("  [!] No DACL or ACEs present")
            continue

        found_escalation = False

        for ace in sd.dacl.aces:
            try:
                sid = ace['Ace']['Sid'].formatCanonical()
                mask = ace['Ace']['Mask']
                acetype = ace['AceType']
                typename = {
                    0x00: "ACCESS_ALLOWED",
                    0x01: "ACCESS_DENIED",
                    0x05: "ACCESS_ALLOWED_OBJECT_ACE_TYPE",
                    0x06: "ACCESS_DENIED_OBJECT_ACE_TYPE"
                }.get(acetype, f"UNKNOWN({acetype})")

                # Check if this ACE contains any escalation rights
                if any(mask & right for right in ESCALATION_RIGHTS):
                    found_escalation = True
                    print(f"  [ACE] Type: {typename}, Mask: {hex(mask)}, SID: {sid}")
                    for bit, right in RIGHTS.items():
                        if mask & bit:
                            print(f"    [+] {right}")
            except Exception as e:
                print(f"  [!] Failed to parse ACE: {e}")

        if not found_escalation:
            print("  [!] No escalation rights found in DACL")
