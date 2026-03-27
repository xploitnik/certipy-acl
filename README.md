#  Certipy-ACL

> LDAP-first ACL enumeration for real privilege escalation paths.

Certipy-ACL is a focused tool for enumerating Active Directory ACLs by reading only `nTSecurityDescriptor`.  
It surfaces **real attack paths** like:

- WriteOwner
- WriteDACL
- GenericAll / GenericWrite
- AddSelf
- DCSync
- ForceChangePassword

---

<img width="1191" height="700" alt="image" src="https://github.com/user-attachments/assets/098a04a2-eb13-4cdd-a26a-38d1264d5dec" />


## Why use this?

-  **Attack-focused output** — shows what you can actually abuse
-  **Quiet enumeration** — minimal LDAP noise
-  **Targeted scanning** — filter by SID or DN
-  **BloodHound-aligned** — same privilege concepts, live from LDAP

---

## 🧩 SID Requirement

Certipy-ACL operates on SIDs (Security Identifiers).  
You are expected to obtain valid SIDs during enumeration.

Common methods:

### 🔹 Impacket
```bash
lookupsid.py $domain.htb/$user:$psswd@$target
```
<img width="600" height="1010" alt="image" src="https://github.com/user-attachments/assets/d1acabed-b67f-42f5-a94b-94e6b73ae1fc" />

## SID Example
<img width="600" height="169" alt="image" src="https://github.com/user-attachments/assets/c58d3050-3b95-490b-891b-6265c999d8ce" />


##  Quick Start

```bash
git clone https://github.com/xploitnik/certipy-acl.git
cd certipy-acl

python3 -m venv .venv
source .venv/bin/activate

pip install -e .
```

---

##  Usage

###  Basic enumeration
```bash
certipy-acl -u $user@$domain -p $psswd -dc-ip $target
```

###  Filter by SID (focus on your user)
```bash
certipy-acl --auth ntlm  -u $user@$domain.htb -p $psswd -d $domain.htb --dc-ip $target --filter-sid $target_sid --resolve-sid
```

###  Limit scope to a DN
```bash
certipy-acl -u $user@$domain -p $psswd -dc-ip $target \
  --target-dn "CN=Users,DC=domain,DC=local"
```

###  Show only escalation paths
```bash
certipy-acl ... --only-escalation
```

---

##  Example Output

```text
certipy-acl --auth ntlm  -u $user@$domain.htb -p $psswd -d $domain.htb --dc-ip $target --filter-sid $taget_sid --resolve-sid
```

<img width="1322" height="600" alt="image" src="https://github.com/user-attachments/assets/cbc36799-bdd9-436e-9075-0efae73a951d" />
michael → can reset password of → Benjamin Brown


##  Supported Privileges

| Privilege | Meaning |
|----------|--------|
| WriteOwner | Take ownership |
| WriteDACL | Modify permissions |
| GenericAll | Full control |
| GenericWrite | Modify attributes |
| AddSelf | Add to group |
| DCSync | Replicate domain secrets |
| ForceChangePassword | Reset user password |

---

##  Auth Options

- NTLM (user + password)
- Kerberos (recommended for OPSEC)

---

##  OPSEC Tip

Use Kerberos whenever possible:

```bash
export KRB5CCNAME=...
certipy-acl -k ...
```

---

##  Goal

Certipy-ACL is built to answer one question:

> **"What can I abuse right now?"**

---

## Author

Built for red teamers, CTF players, and operators who want **signal over noise**.















