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
Start with any valid domain user. You can directly enumerate user objects and their raw SIDs.

---
```bash
ldapsearch -H ldap://xx.xx.xx.xx \
  -D "user@local.htb" \
  -w 'Password' \
  -b "DC=local,DC=local" \
  "(|(objectClass=user)(objectClass=group))" \
  sAMAccountName objectSid > raw_sids.ldif

```
---

### 2. 📚 **Decode SIDs and Build Your Map**
Convert base64 `objectSid` values to canonical SID format with a helper script or parser.

---
python3 scripts/decode_sids.py raw_sids.ldif > resolved_sids.txt
---

Example output:
S-1-5-21-...-1103 = judith.mader  
S-1-5-21-...-1154 = management_svc  
...

---

### 3. 🧠 **Use Certipy-ACL to Analyze ACLs**
Run the tool as your low-privileged user. You don’t need DA access — just a valid bind.

---
python3 -m certipy_tool \
  -u 'judith.mader@certified.htb' \
  -p 'judith09' \
  -d certified.htb \
  --dc-ip 10.129.164.230 \
  --resolve-sids \
  --hits-only
---

This will enumerate all DACLs that Judith can read and display ACEs matching escalation-relevant rights.

---

### 4. 🎯 **Filter by Any SID to Pivot**
Once you have the SID map, you can filter for *any user or group* — even those you haven’t compromised yet.

#### 1. 🔓 LDAP Bind as a Low-Privileged User
Start with any valid domain user. You can directly enumerate user objects and their raw SIDs.

---
ldapsearch -H ldap://<DC_IP> \
  -D 'judith.mader@certified.htb' \
  -w 'judith09' \
  -b 'DC=certified,DC=htb' \
  -s sub '(objectClass=user)' \
  sAMAccountName objectSid > raw_sids.ldif
---

## 🧨 Why This Is Powerful

- ✅ Pure LDAP — no SMB, RPC, or Kerberos noise  
- ✅ Discover escalation paths without touching BloodHound  
- ✅ Works with **any SID** your bind user can read  
- ✅ Red teamers can **pivot quietly**  
- ✅ Blue teamers can **map real privilege relationships**  

---

## 💡 Tip: Save and Reuse SID Maps

Save decoded SIDs into JSON/text for re-use:

---
{
  "S-1-5-21-729746778-2675978091-3820388244-1103": "judith.mader",
  "S-1-5-21-729746778-2675978091-3820388244-1154": "management_svc"
}
---

---

## 📘 Real-World Use Case

In one HTB box, this strategy revealed that `management_svc` had `WriteOwner` over another privileged user — discovered without BloodHound or SMB scans.

---

## ✅ Final Thought

**You don’t need domain admin access to map privilege.**  
One valid LDAP bind + ACL mindset is enough to silently chart escalation paths.

