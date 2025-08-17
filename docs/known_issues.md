# 🧠 Known Limitation: Why Some ACLs Show **No ACEs** (Even When They Exist)

**Certipy-ACL** reads *real* AD ACLs via LDAP with a single bind. It’s quiet and precise—but there’s one important constraint to understand up front.

---

## ❗ TL;DR

If you see:

[ACL] CN=SomeObject,CN=Users,DC=domain,DC=local
[!] No DACL or ACEs present


…it usually means the account you bound with **cannot read the DACL** for that object. The ACEs may still exist; the server is simply **not returning** them.

---

## 🔍 Root Cause

- AD stores permissions in `nTSecurityDescriptor` (which contains the **DACL**).
- Reading the DACL requires **READ_CONTROL** on the object.
- If your principal **lacks READ_CONTROL**, LDAP omits the DACL from the response.  
  → No DACL returned ⇒ nothing for Certipy-ACL to parse.

This can happen even if you actually *hold powerful rights* (e.g., `WriteOwner`, `WriteDACL`, `GenericAll`) but aren’t allowed to **read** the security descriptor.

---

## 🧪 How to Recognize It

- “No DACL or ACEs present” appears for some objects, while others decode fine.  
- You might still be able to modify the object (separate write rights).  
- With `--verbose`, LDAP responses for affected objects **lack** `nTSecurityDescriptor`.

---

## 💡 Workarounds

1. **Bind with an account that has READ_CONTROL** on the target objects.  
2. **Limit scope** to where you *do* have READ_CONTROL (`--enum-base` for OUs, `--target-dn` for one object).  
3. **Obtain the security descriptor via another channel** and decode offline (export from a host/account with sufficient rights).  
4. **Suspect a bug?** Run with `--verbose`, capture a redacted sample, and open an issue. If the SD attribute is missing, it’s a visibility issue—not parsing.

---

## 🧩 Why This Isn’t a Tool Bug

Certipy-ACL does not “guess” or simulate graphs; it decodes **what LDAP returns**.  
If LDAP doesn’t send the DACL (because READ_CONTROL is missing), the tool correctly reports **no ACEs**.

---

## ✅ Summary

- “No DACL or ACEs present” is almost always a **permissions/visibility** problem (missing READ_CONTROL).  
- The DACL may still exist; LDAP just didn’t return it.  
- Use a principal that can read the SD, narrow scope to visible areas, or decode an SD acquired through another path.

Stay stealthy—and if you discover a reliable, low-noise way to read DACLs without READ_CONTROL, please open a PR or issue. 🔎
