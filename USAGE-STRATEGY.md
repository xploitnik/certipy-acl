# 🧠 USAGE STRATEGY — Certipy ACL

This guide explains how to **maximize the power of the `certipy-acl` tool** by combining low-privileged LDAP access with SID-focused privilege enumeration.

---

## 🔐 In a Nutshell

> With a single low-privileged LDAP bind, you can:
>
> - Enumerate all domain users and groups
> - Extract and decode their SIDs
> - Filter ACEs by any SID using `--filter-sid`
> - Map real privilege paths (e.g., `GenericAll`, `WriteOwner`, `WriteDACL`)
> - Discover who controls who — **silently**, without triggering alerts

---

## 🧩 Methodology Overview

### 1. 🔓 **LDAP Bind as a Low-Privileged User**
Start with any valid domain user.
```bash
ldapsearch -H ldap://<DC_IP> \
  -D 'judith.mader@certified.htb' \
  -w 'judith09' \
  -b 'DC=certified,DC=htb' \
  -s sub '(objectClass=user)' \
  sAMAccountName objectSid > raw_sids.ldif
```

---

### 2. 📚 **Decode SIDs and Build Your Map**
Use a custom script to convert base64 `objectSid` values to standard SID format:
```bash
python3 scripts/decode_sids.py raw_sids.ldif > resolved_sids.txt
```

This gives you a mapping like:
```
S-1-5-21-...-1103 = judith.mader
S-1-5-21-...-1154 = management_svc
...
```

---

### 3. 🧠 **Use Certipy-ACL to Analyze ACLs**
Run the tool as your low-privileged user. You don’t need DA access.

```bash
python3 -m certipy_tool \
  -u 'judith.mader@certified.htb' \
  -p 'judith09' \
  -target certified.htb \
  -dc-ip 10.129.164.230 \
  --resolve-sids
```

This will enumerate all DACLs that Judith can read and extract any ACEs where her SID appears.

---

### 4. 🎯 **Filter by Any SID to Pivot**
Once you have all known SIDs, you can filter for *any user or group* — even ones you haven't compromised yet.

```bash
python3 -m certipy_tool \
  -u 'judith.mader@certified.htb' \
  -p 'judith09' \
  -target certified.htb \
  -dc-ip 10.129.164.230 \
  --resolve-sids \
  --filter-sid S-1-5-21-...-1154
```

This tells you **what objects the target SID controls** — e.g., `management_svc` may have `GenericAll` over another user.

---

## 🧨 Why This Is Powerful

- ✅ Pure LDAP — no SMB, RPC, or Kerberos noise
- ✅ Discover escalation paths without touching BloodHound
- ✅ Works with **any SID** as long as your bind user can read the object’s DACL
- ✅ Helps red teamers **pivot quietly**
- ✅ Helps blue teamers **understand real privilege relationships**

---

## 💡 Tip: Save and Reuse SID Maps

Save all decoded SIDs into a JSON or text file to reuse across boxes or tool runs.

```json
{
  "S-1-5-21-729746778-2675978091-3820388244-1103": "judith.mader",
  "S-1-5-21-729746778-2675978091-3820388244-1154": "management_svc",
  ...
}
```

---

## 📘 Real-World Use Case

> In one HTB box, we used this technique to discover that `management_svc` had `WriteOwner` over another privileged user — all without touching BloodHound or scanning SMB shares.

---

## ✅ Final Thought

**You don’t need domain admin access to map privilege.**  
All you need is one valid bind — and the ability to think in terms of ACLs, not just shells.

---
