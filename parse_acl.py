RIGHTS = {
    0x00000001: "ReadProperty",
    0x00000002: "WriteProperty",
    0x00000004: "CreateChild",
    0x00000008: "DeleteChild",
    0x00000010: "ListChildren",
    0x00000020: "Self",
    0x00000040: "ReadControl",
    0x00000100: "Delete",
    0x00020000: "WriteDACL",
    0x00080000: "WriteOwner",
    0x01000000: "GenericRead",
    0x02000000: "GenericWrite",
    0x04000000: "GenericExecute",
    0x08000000: "GenericAll",
}

ACE_TYPE_NAMES = {
    0x00: "ACCESS_ALLOWED",
    0x01: "ACCESS_DENIED",
    0x05: "ACCESS_ALLOWED_OBJECT_ACE_TYPE",
    0x06: "ACCESS_DENIED_OBJECT_ACE_TYPE",
}

def parse_acl_entries(entries, resolve=False, only_users=False, sid_filter=None):
    for dn, sd, obj_classes in entries:
        if only_users:
            if not any(cls.lower() in ["user", "person", "inetorgperson"] for cls in obj_classes):
                continue

        print(f"\n[ACL] {dn}")
        if not hasattr(sd, "dacl") or sd.dacl is None:
            print("  [!] No DACL or ACEs present")
            continue

        found = False
        for ace in sd.dacl.aces:
            acetype = ace['AceType']
            typename = ACE_TYPE_NAMES.get(acetype, f"UNKNOWN({acetype})")
            mask = ace['Ace']['Mask']
            sid = ace['Ace']['Sid'].formatCanonical()

            # SID filter: skip if not matching
            if sid_filter and sid != sid_filter:
                continue

            resolved = sid
            if resolve:
                try:
                    from certipy_tool.auth import ldap_instance
                    resolved = ldap_instance.resolve_sid(sid)
                except Exception:
                    pass

            print("  🔐 ACE Summary:")
            print(f"    ACE Type:       {typename}")
            print(f"    SID:            {sid}")
            print(f"    Resolved SID:   {resolved}")
            print(f"    Rights:")

            for bit, right in RIGHTS.items():
                if mask & bit:
                    print(f"      ✅ {right}")
                    found = True

        if not found:
            print("    [!] No matching rights found.")


