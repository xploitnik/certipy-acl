# 🧠 USAGE STRATEGY — Certipy ACL

This guide explains how to maximize the power of the certipy-acl tool by combining low-privileged LDAP access with SID-focused privilege enumeration.

---

## 🔐 In a Nutshell

With a single low-privileged LDAP bind, you can:
- Enumerate all domain users and groups
- Extract and decode their SIDs
- Filter ACEs by any SID using --filter-sid
- Map real privilege paths (e.g., GenericAll, WriteOwner, WriteDACL)
- Discover who controls who — silently, without triggering alerts

---

## 🧩 Methodology Overview

### 1) LDAP Bind as a Low-Privileged User
Start with any valid domain user to dump objects and raw SIDs.
```
ldapsearch -H ldap://<DC_IP> \
  -D "user@domain.local" \
  -w 'Password' \
  -b "DC=domain,DC=local" \
  "(|(objectClass=user)(objectClass=group))" \
  sAMAccountName objectSid > raw_sids.ldif
```
---
### 2. 📚 Decode SIDs and Build Your Map

The attribute `objectSid` comes base64-encoded in LDAP output.  
```
sAMAccountName: Management
objectSid:: AQUAAAAAAAUVAAAAWg1/K2svgJ+Uf7bj9AEAAA==

sAMAccountName: Administrator
objectSid:: AQUAAAAAAAUVAAAAWg1/K2svgJ+Uf7bjTwQAAA==

sAMAccountName: judith.mader
objectSid:: AQUAAAAAAAUVAAAAWg1/K2svgJ+Uf7bjUQQAAA==
```

To convert it into a readable SID format, the easiest way is **CyberChef**:

1. Copy the base64 string after `objectSid::` from your `raw_sids.ldif`.  
2. Open [CyberChef](https://gchq.github.io/CyberChef/).  
3. Add the operation **“From Base64”**.  
4. Then add **“SID Decode”** (or view as hex and apply a SID decoding recipe).  

Example mapping after decoding:
```
Management       --> S-1-5-21-729746778-2675978091-3820388244-1104
Administrator    --> S-1-5-21-729746778-2675978091-3820388244-500
judith.mader     --> S-1-5-21-729746778-2675978091-3820388244-1103
management_svc   --> S-1-5-21-729746778-2675978091-3820388244-1105
```
---

### 3) Use Certipy-ACL to Analyze ACLs

Run the tool with your low-privileged account. No DA needed.
This enumerates all DACLs the user can read and highlights escalation-relevant ACEs.

```
python3 -m certipy_tool \
  -u 'judith.mader@certified.htb' \
  -p 'judith09' \
  -d certified.htb \
  --dc-ip 10.129.164.230 \
  --resolve-sids \
  --hits-only
```
---

### 4) Filter by Any SID to Pivot

With your SID map, pivot by checking control for other accounts.
```
python3 -m certipy_tool \
  -u 'judith.mader@certified.htb' \
  -p 'judith09' \
  -d certified.htb \
  --dc-ip 10.129.164.230 \
  --resolve-sids \
  --filter-sid S-1-5-21-...-1154 \
  --hits-only
```
This shows what objects the chosen SID controls (e.g., management_svc → GenericAll over another user).

---

## 🧨 Why This Is Powerful

- Pure LDAP — no SMB, RPC, or Kerberos noise
- Discover escalation paths without BloodHound
- Works with any SID you can read
- Red teamers can pivot quietly
- Blue teamers can map real privilege relationships

---

## 💡 Tip: Save and Reuse SID Maps

Keep a JSON or text file with decoded SIDs for re-use:

---
```
{ "S-1-5-21-729746778-2675978091-3820388244-1103": "judith.mader",
  "S-1-5-21-729746778-2675978091-3820388244-1154": "management_svc" }
```
---

## 📘 Real-World Use Case

In one HTB box, this method revealed that management_svc had WriteOwner over another privileged user — discovered silently without BloodHound.

---

## ✅ Final Thought

You don’t need domain admin to map privilege. One valid LDAP bind + ACL mindset = stealth escalation discovery.

