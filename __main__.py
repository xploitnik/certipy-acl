#!/usr/bin/env python3
# __main__.py
import argparse

# Soportar ejecución como paquete (python -m certipy_tool) y también directa
try:
    from .auth import (
        bind_ldap, build_base_dn, get_user_dn_and_sid,
        get_effective_token_sids, paged_search_dns, resolve_sid_name
    )
    from .parse_acl import check_writeowner_for_dn, enumerate_acls_for_sid
except ImportError:
    # fallback si alguien ejecuta el archivo suelto, fuera de paquete
    from auth import (
        bind_ldap, build_base_dn, get_user_dn_and_sid,
        get_effective_token_sids, paged_search_dns, resolve_sid_name
    )
    from parse_acl import check_writeowner_for_dn, enumerate_acls_for_sid


def main():
    ap = argparse.ArgumentParser(
        description="certipy_tool: enumeración de ACLs filtrando por SID y chequeo de WriteOwner"
    )
    ap.add_argument("-u", "--username", required=True, help="UPN o DOMAIN\\sam")
    ap.add_argument("-p", "--password", required=True)
    ap.add_argument("-d", "--domain", required=True, help="FQDN del dominio (p.ej. certified.htb)")
    ap.add_argument("--dc-ip", required=True, help="IP del DC")
    ap.add_argument("--filter-sid", help="Solo mostrar ACEs que referencian este SID")
    ap.add_argument("--size-limit", type=int, default=0, help="Máximo de objetos a recorrer")
    ap.add_argument("--check-writeowner", action="store_true", help="Chequear WriteOwner sobre un objeto")
    ap.add_argument("--target-dn", help="DN objetivo (por defecto: CN=Management,CN=Users,DC=...)", default=None)
    ap.add_argument("--verbose", action="store_true", help="Salida detallada en check-writeowner")
    args = ap.parse_args()

    base_dn = build_base_dn(args.domain)
    target_dn = args.target_dn or f"CN=Management,CN=Users,{base_dn}"

    print(f"[INFO] DC: {args.dc_ip}")
    print(f"[INFO] Domain: {args.domain}")
    print(f"[INFO] BaseDN: {base_dn}")
    print(f"[INFO] Target DN: {target_dn}")

    print("[AUTH] Binding to LDAP...")
    conn = bind_ldap(args.dc_ip, args.domain, args.username, args.password)
    print("[AUTH] LDAP bind successful.")

    # Datos del usuario y token (necesario para check-writeowner)
    user_dn, user_sid = get_user_dn_and_sid(conn, args.username, base_dn)
    print(f"[INFO] User DN: {user_dn}")
    print(f"[INFO] User SID: {user_sid}")
    eff_sids = get_effective_token_sids(conn, user_dn, user_sid)
    print(f"[INFO] Effective token SIDs: {len(eff_sids)}")

    if args.check_writeowner:
        ok, msgs = check_writeowner_for_dn(conn, target_dn, eff_sids, verbose=args.verbose)
        for m in msgs:
            print(m)
        return

    # Enumeración filtrada por SID (si se pide)
    if args.filter_sid:
        print(f"[AUTH] Searching LDAP tree under {base_dn} ...")
        dns = paged_search_dns(conn, base_dn, size_limit=args.size_limit)
        enumerate_acls_for_sid(conn, dns, args.filter_sid, resolve_sid_name, base_dn)
    else:
        print("[INFO] No se proporcionó --filter-sid. Nada que enumerar. Usa --filter-sid o --check-writeowner.")


if __name__ == "__main__":
    main()

