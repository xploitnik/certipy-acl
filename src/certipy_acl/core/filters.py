from .rights import RIGHTS, KEY_RIGHTS

def _format_ace(ace, resolve):
    sid = ace['Ace']['Sid'].formatCanonical()
    # Placeholder for SID resolution hook if you wire it later
    mask = ace['Ace']['Mask']
    acetype = ace['AceType']
    typename = {
        0x00: "ACCESS_ALLOWED",
        0x01: "ACCESS_DENIED",
        0x05: "ACCESS_ALLOWED_OBJECT",
        0x06: "ACCESS_DENIED_OBJECT",
    }.get(acetype, f"UNKNOWN({acetype})")

    rights_list = [name for bit, name in RIGHTS.items() if mask & bit]
    return sid, typename, mask, rights_list

class RightsFilter:
    """Parses a security descriptor, optionally filtering by SID and key rights."""

    def __init__(self, only_escalation: bool = False):
        self.only_escalation = only_escalation

    def parse_object(self, dn, sd, filter_sid=None, resolve_sid=False, verbose=False):
        out_lines = [f"[ACL] {dn}"]
        matched = False

        if not hasattr(sd, "dacl") or sd.dacl is None:
            out_lines.append("  [!] No DACL or ACEs present")
            return {"matched": False, "render": "\n".join(out_lines)}

        any_ace = False
        for ace in sd.dacl.aces:
            any_ace = True
            sid, typename, mask, rights_list = _format_ace(ace, resolve_sid)
            if filter_sid and sid != filter_sid:
                continue

            show_rights = rights_list
            if self.only_escalation:
                show_rights = [r for r in rights_list if r in KEY_RIGHTS]

            if show_rights:
                matched = True

            out_lines.append(f"  🔐 ACE: {typename} | SID: {sid} | Mask: 0x{mask:08X}")
            if show_rights:
                for r in show_rights:
                    out_lines.append(f"    [+] {r}")
            else:
                if verbose:
                    out_lines.append("    [!] No matching rights found.")

        if not any_ace:
            out_lines.append("  [!] No ACEs in DACL")

        return {"matched": matched, "render": "\n".join(out_lines)}
