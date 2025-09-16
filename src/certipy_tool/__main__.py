# certipy_tool/__main__.py
# -*- coding: utf-8 -*-
#
# CLI principal para Certipy-ACL.
# Ahora soporta NTLM y Kerberos (GSSAPI).
#
import sys
import argparse

from .auth import LDAPSocket
from .parse_acl import (
    parse_acl_entries,
    enumerate_acls_for_sid,
    check_writeowner_for_dn,
)

BANNER = """\
[Certipy-ACL] Lightweight LDAP ACL mapper (silent bind)
"""

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Certipy-ACL — Enumeración de ACEs/ACLs vía un único bind LDAP",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Autenticación
    p.add_argument("--auth", choices=["ntlm", "kerberos"], default="ntlm",
                   help="Método de autenticación LDAP (por defecto: ntlm)")
    p.add_argument("-u", "--username", help="Usuario (UPN o sAMAccountName). Obligatorio para NTLM.")
    p.add_argument("-p", "--password", help="Contraseña. Obligatoria para NTLM.")
    p.add_argument("-d", "--domain",   required=True, help="FQDN del dominio, p.ej. certified.htb")
    p.add_argument("--dc-ip",          required=True, help="IP del DC a consultar")
    p.add_argument("--dc-host", help="FQDN del DC (p.ej. dc.rustykey.htb). Recomendado para Kerberos.")
    p.add_argument("--ccache", help="Ruta al ccache Kerberos (opcional, si no se usa el default)")

    # Filtros / opciones
    p.add_argument("--filter-sid", help="SID a filtrar (muestra sólo ACEs de este trustee)")
    p.add_argument("--target-dn",  help="DN base/objetivo para limitar el sub-árbol")

    # Output / comportamiento
    p.add_argument("--size-limit", type=int, default=0,
                   help="Limitar nº de objetos procesados (0 = sin límite)")
    p.add_argument("--check-writeowner", action="store_true",
                   help="Chequear solo si el SID filtrado tiene WriteOwner sobre --target-dn.")

    # Compatibilidad y UX
    p.add_argument("--only-escalation", dest="only_escalation", action="store_true",
                   help="Mostrar sólo ACEs con derechos de escalada (WriteOwner/WriteDACL/GenericAll/GenericWrite).")
    p.add_argument("--hits-only", dest="only_escalation", action="store_true",
                   help="Alias de --only-escalation.")
    p.add_argument("--resolve-sids", action="store_true",
                   help="Intentar resolver SIDs a nombres usando el socket LDAP.")
    p.add_argument("--ldaps", action="store_true", help="Usar LDAPS si está disponible.")
    p.add_argument("--starttls", action="store_true", help="Negociar StartTLS en LDAP (si no se usa --ldaps).")
    p.add_argument("--no-bh-compat", dest="bh_compat", action="store_false",
                   help="Desactiva la marca de GenericWrite (derived) por WriteProperty/Self.")
    p.add_argument("--verbose", action="store_true", help="Salida más verbosa.")
    p.set_defaults(bh_compat=True)

    return p


def main() -> int:
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        print(f"[INFO] DC: {args.dc_ip}")
        print(f"[INFO] Domain: {args.domain}")
        if args.dc_host:
            print(f"[INFO] DC Host (FQDN): {args.dc_host}")
        if args.target_dn:
            print(f"[INFO] Target DN: {args.target_dn}")
        if args.filter_sid:
            print(f"[INFO] Filter SID: {args.filter_sid}")
        print(f"[INFO] Auth method: {args.auth}")

    # Conectar: NTLM → --dc-ip; Kerberos → preferimos FQDN
    target_host = args.dc_ip if args.auth == "ntlm" else (args.dc_host or f"dc.{args.domain}")

    try:
        print("[AUTH] Binding to LDAP...")
        if args.auth == "ntlm":
            if not args.username or not args.password:
                print("[ERROR] NTLM requiere -u/--username y -p/--password.")
                return 2

        sock = LDAPSocket(
            target=target_host,
            username=args.username or "",
            password=args.password or "",
            domain=args.domain,
            dc_ip=args.dc_ip,
            use_ldaps=args.ldaps,
            auth_method=args.auth,
            ccache=args.ccache,
            dc_fqdn=args.dc_host or None,
            starttls=args.starttls,
        )
        print("[AUTH] LDAP bind successful.")
    except Exception as e:
        print(f"[ERROR] Falló el bind LDAP: {e}")
        return 1

    resolver = None
    if args.resolve_sids:
        maybe = getattr(sock, "resolve_sid", None)
        if callable(maybe):
            resolver = maybe
        elif args.verbose:
            print("[WARN] resolve_sid() no disponible.")

    # Check puntual
    if args.check_writeowner:
        if not args.filter_sid or not args.target_dn:
            print("[ERROR] --check-writeowner requiere --filter-sid y --target-dn.")
            return 2
        ok = check_writeowner_for_dn(sock, args.target_dn, args.filter_sid)
        return 0 if ok else 3

    # Enumeración normal
    try:
        if args.size_limit and args.size_limit > 0:
            entries = sock.get_effective_control_entries()
            if args.target_dn:
                base_l = args.target_dn.lower()
                entries = [(dn, sd) for dn, sd in entries
                           if dn.lower() == base_l or dn.lower().endswith("," + base_l)]
            entries = entries[: args.size_limit]

            if args.verbose:
                print(f"[INFO] Objetos a procesar (limit): {len(entries)}")
            parse_acl_entries(
                entries,
                filter_sid=args.filter_sid,
                resolve_sid=resolver,
                only_escalation=args.only_escalation,
                bh_compat=args.bh_compat,
            )
        else:
            enumerate_acls_for_sid(
                sock=sock,
                filter_sid=args.filter_sid,
                target_dn=args.target_dn,
                resolve_sid=resolver,
                only_escalation=args.only_escalation,
                bh_compat=args.bh_compat,
            )
    except Exception as e:
        print(f"[ERROR] Enumeración falló: {e}")
        return 5

    return 0


if __name__ == "__main__":
    sys.exit(main())



