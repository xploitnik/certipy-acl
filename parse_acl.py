# certipy_tool/parse_acl.py

"""
Parser de DACLs para Certipy-ACL.
- Normaliza ACCESS_MASK (objeto) a int para hacer operaciones bit a bit sin errores.
- Resalta primero derechos de escalada (WriteOwner, WriteDACL, GenericAll, GenericWrite).
- Cuando NO se pasa --filter-sid, ignora ACEs fuera del SID de dominio actual
  y fuera de los grupos built-in (S-1-5-32-XXXX).
- Imprime Mask (hex) para depuración.
"""

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

# Derechos de escalada a resaltar
ESC_RIGHTS = {"WriteOwner", "WriteDACL", "GenericAll", "GenericWrite"}

ACE_TYPE_NAMES = {
    0x00: "ACCESS_ALLOWED",
    0x01: "ACCESS_DENIED",
    0x05: "ACCESS_ALLOWED_OBJECT_ACE_TYPE",
    0x06: "ACCESS_DENIED_OBJECT_ACE_TYPE",
}

def _mask_to_int(mask_obj):
    """
    Normaliza distintas representaciones de ACCESS_MASK a int.
    Evita TypeError al hacer 'mask & bit'.
    """
    # 1) muchas veces ya castea a int
    try:
        return int(mask_obj)
    except Exception:
        pass
    # 2) algunos objetos tienen .value
    try:
        return int(getattr(mask_obj, "value", mask_obj))
    except Exception:
        pass
    # 3) fallback: si viene como dict con clave 'Mask'
    try:
        return int(mask_obj.get("Mask"))
    except Exception:
        pass
    # 4) último recurso
    return 0

def _domain_sid_prefix(canonical_sid: str):
    """
    'S-1-5-21-...-RID' -> 'S-1-5-21-...'
    """
    parts = canonical_sid.split("-")
    if len(parts) >= 5:
        return "-".join(parts[:-1])
    return None

def parse_acl_entries(entries, resolve=False, only_users=False, sid_filter=None, ldap=None):
    """
    entries: lista de tuplas (dn, sd, obj_classes)
    resolve: si True, resuelve SID a sAMAccountName
    only_users: si True, imprime solo objetos de tipo usuario/persona
    sid_filter: si se pasa, muestra únicamente ACEs cuyo SID sea exactamente ese
    ldap: instancia LDAPSocket (para resolver SIDs y conocer el SID de la cuenta actual)
    """
    # Prefijo del dominio para filtrar ACEs si no se pasa sid_filter
    domain_prefix = None
    if sid_filter is None and ldap is not None and getattr(ldap, "user_sid", None):
        domain_prefix = _domain_sid_prefix(ldap.user_sid)

    for dn, sd, obj_classes in entries:
        # Filtrar por clase de objeto si piden solo usuarios
        if only_users:
            if not any(cls.lower() in ["user", "person", "inetorgperson"] for cls in obj_classes):
                continue

        print(f"\n[ACL] {dn}")

        # Impacket expone Dacl (D mayúscula). Permite acceso por índice o atributo.
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
        any_rights_printed = False

        for ace in aces:
            try:
                acetype = ace["AceType"]
                typename = ACE_TYPE_NAMES.get(acetype, f"UNKNOWN({acetype})")

                # SID canónico del ACE
                sid = ace["Ace"]["Sid"].formatCanonical()

                # Filtro por SID exacto, si lo pasan
                if sid_filter and sid != sid_filter:
                    continue

                # Si NO hay sid_filter, ignora ACEs fuera del dominio actual y built-ins
                if sid_filter is None and domain_prefix is not None:
                    if not (sid.startswith(domain_prefix) or sid.startswith("S-1-5-32-")):
                        continue

                any_ace_matched_sid = True

                # Normaliza máscara a int y opcionalmente resuelve el SID
                mask_int = _mask_to_int(ace["Ace"]["Mask"])

                resolved = sid
                if resolve and ldap is not None:
                    try:
                        resolved = ldap.resolve_sid(sid) or sid
                    except Exception:
                        resolved = sid

                print("  🔐 ACE Summary:")
                print(f"    ACE Type:       {typename}")
                print(f"    SID:            {sid}")
                print(f"    Resolved SID:   {resolved}")
                print(f"    Mask (hex):     0x{mask_int:08x}")
                print(f"    Rights:")

                rights_matched = []

                # 1) Primero los derechos de escalada, en orden de impacto
                esc_order = ["WriteOwner", "WriteDACL", "GenericAll", "GenericWrite"]
                for bit, name in RIGHTS.items():
                    if name in esc_order and (mask_int & bit):
                        rights_matched.append(name)

                # 2) Luego el resto
                for bit, name in RIGHTS.items():
                    if name not in esc_order and (mask_int & bit):
                        rights_matched.append(name)

                if rights_matched:
                    for r in rights_matched:
                        print(f"      ✅ {r}")
                    any_rights_printed = True
                else:
                    print("      [–] (No standard rights matched for this ACE mask)")

            except Exception as e:
                print(f"  [WARN] Failed to parse an ACE on this object: {e}")

        if sid_filter and not any_ace_matched_sid:
            print(f"    [!] No ACEs referencing SID {sid_filter} on this object.")

        if not any_rights_printed:
            print("    [!] No matching rights found.")




