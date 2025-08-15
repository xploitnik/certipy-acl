# certipy_tool/parse_acl.py

# === Directory Service Specific Rights (low bits 0..8) ===
DS_SPECIFIC_RIGHTS = {
    0x00000001: "CreateChild",
    0x00000002: "DeleteChild",
    0x00000004: "ListChildren",
    0x00000008: "Self",
    0x00000010: "ReadProperty",
    0x00000020: "WriteProperty",
    0x00000040: "DeleteTree",
    0x00000080: "ListObject",
    0x00000100: "ControlAccess",  # Extended (guid-based) gate
}

# === Standard Rights (higher, but below generic) ===
STANDARD_RIGHTS = {
    0x00010000: "Delete",
    0x00020000: "ReadControl",
    0x00040000: "WriteDACL",
    0x00080000: "WriteOwner",
    0x00100000: "Synchronize",
}

# === Generic Rights (very high bits) ===
GENERIC_RIGHTS = {
    0x10000000: "GenericAll",
    0x20000000: "GenericExecute",
    0x40000000: "GenericWrite",
    0x80000000: "GenericRead",
}

# Conjunto completo para iterar en orden "bonito"
RIGHTS_ORDERED = [
    ("DirectorySpecific", DS_SPECIFIC_RIGHTS),
    ("Standard", STANDARD_RIGHTS),
    ("Generic", GENERIC_RIGHTS),
]

# Derechos clave para el "quick check"
KEY_BITS = {
    0x00080000: "WriteOwner",
    0x00040000: "WriteDACL",
    0x10000000: "GenericAll",
    0x40000000: "GenericWrite",
    0x80000000: "GenericRead",
    0x00010000: "Delete",
}

ACE_TYPE_NAMES = {
    0x00: "ACCESS_ALLOWED",
    0x01: "ACCESS_DENIED",
    0x05: "ACCESS_ALLOWED_OBJECT_ACE_TYPE",
    0x06: "ACCESS_DENIED_OBJECT_ACE_TYPE",
}

# --- Expansión de genéricos ---
def expand_generic_for_directory(mask: int) -> int:
    """
    Expande GENERIC_* a derechos estándar/específicos típicos de objetos de Directorio en AD.
    Nota: mapeos usados comúnmente; suficientes para el quick check (WriteOwner, WriteDACL, etc.).
    """
    expanded = mask

    if mask & 0x10000000:  # GenericAll
        expanded |= (
            0x00010000 |  # Delete
            0x00020000 |  # ReadControl
            0x00040000 |  # WriteDACL
            0x00080000 |  # WriteOwner
            0x00000010 |  # ReadProperty
            0x00000020 |  # WriteProperty
            0x00000004 |  # ListChildren
            0x00000080 |  # ListObject
            0x00000100 |  # ControlAccess
            0x00000008    # Self
        )

    if mask & 0x40000000:  # GenericWrite
        expanded |= (0x00000020 | 0x00000008 | 0x00020000)

    if mask & 0x80000000:  # GenericRead
        expanded |= (0x00000010 | 0x00000004 | 0x00000080 | 0x00020000)

    if mask & 0x20000000:  # GenericExecute
        expanded |= (0x00000004 | 0x00000080 | 0x00020000)

    return expanded

def _mask_to_int(mask_obj) -> int:
    """Convierte el Mask del ACE a int de forma robusta."""
    try:
        return int(mask_obj)
    except Exception:
        pass

    for attr in ("value", "mask"):
        try:
            v = getattr(mask_obj, attr, None)
            if v is not None:
                return int(v)
        except Exception:
            pass

    try:
        s = str(mask_obj).strip()
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        if s.isdigit():
            return int(s)
    except Exception:
        pass

    return 0

def parse_acl_entries(entries, resolve=False, only_users=False, sid_filter=None, ldap=None):
    """
    entries: [(dn, sd, obj_classes), ...]
    resolve: resolver SID -> sAMAccountName
    only_users: mostrar solo objetos de usuario/persona
    sid_filter: S-1-5-... exacto
    ldap: LDAPSocket para resolver SIDs (opcional)
    """
    for dn, sd, obj_classes in entries:
        if only_users:
            if not any((obj_classes or []) and cls.lower() in ("user", "person", "inetorgperson") for cls in obj_classes):
                continue

        print(f"\n[ACL] {dn}")

        # Obtener DACL (Impacket usa "Dacl")
        dacl = None
        try:
            dacl = sd["Dacl"] if (isinstance(sd, dict) or hasattr(sd, "__getitem__")) else getattr(sd, "Dacl", None)
        except Exception:
            dacl = getattr(sd, "Dacl", None)

        if dacl is None:
            print("  [!] No DACL or ACEs present")
            continue

        aces = getattr(dacl, "aces", None)
        if not aces:
            print("  [!] DACL present but has no ACEs")
            continue

        any_ace_matched_sid = False
        any_rights_printed_for_object = False

        for ace in aces:
            try:
                acetype = ace["AceType"]
                typename = ACE_TYPE_NAMES.get(acetype, f"UNKNOWN({acetype})")

                inner = ace["Ace"]
                mask_raw = inner["Mask"]
                sid = inner["Sid"].formatCanonical()

                if sid_filter and sid != sid_filter:
                    continue
                any_ace_matched_sid = True

                resolved = sid
                if resolve and ldap is not None:
                    try:
                        r = ldap.resolve_sid(sid)
                        if r:
                            resolved = r
                    except Exception:
                        pass

                mask_val = _mask_to_int(mask_raw)
                expanded_mask = expand_generic_for_directory(mask_val)

                print("  🔐 ACE Summary:")
                print(f"    ACE Type:       {typename}")
                print(f"    SID:            {sid}")
                print(f"    Resolved SID:   {resolved}")
                print(f"    Mask (hex):     0x{mask_val:08X}")

                # Mostrar genéricos presentes en la máscara original
                generic_present = [name for bit, name in GENERIC_RIGHTS.items() if (mask_val & bit) != 0]
                if generic_present:
                    print(f"    Generic (raw):  {', '.join(generic_present)}")

                print("    Rights:")

                matched_bits = set()
                matches_in_this_ace = 0

                # Mostrar por categorías usando la máscara EXPANDIDA
                for cat_name, mapping in RIGHTS_ORDERED:
                    for bit, name in mapping.items():
                        if (expanded_mask & bit) != 0:
                            print(f"      ✅ {name}")
                            matches_in_this_ace += 1
                            matched_bits.add(bit)
                            any_rights_printed_for_object = True

                unknown = expanded_mask
                for bit in matched_bits:
                    unknown &= ~bit
                if matches_in_this_ace == 0:
                    print("      [–] (No standard rights matched for this ACE mask)")
                if unknown != 0:
                    print(f"      … Unknown bits: 0x{unknown:08X}")

                # Chequeo rápido de derechos clave usando máscara expandida
                print("    Key rights (quick check):")
                for bit, name in KEY_BITS.items():
                    has_it = (expanded_mask & bit) != 0
                    print(f"      - {name}: {'YES' if has_it else 'NO'}")

            except Exception as e:
                print(f"  [!] Error parsing ACE on {dn}: {e}")
                continue

        if sid_filter and not any_ace_matched_sid:
            print(f"    [!] No ACEs referencing SID {sid_filter} on this object.")

        if not any_rights_printed_for_object:
            print("    [!] No matching rights found.")






