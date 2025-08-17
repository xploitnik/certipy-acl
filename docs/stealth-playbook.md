# 🎭 Stealth Playbook — Certipy-ACL

Practical guide to use `certipy-acl` with different **noise levels** in Active Directory and pick the right command based on your objective and OPSEC.

---

## 🔧 Key Flags (Quick Reference)

- `--filter-sid <SID>` → show only ACEs that affect a specific SID (user/group).
- `--target-dn '<DN>'` → limit to **one specific object** (surgical).
- `--enum-base '<DN>'` → limit the scan to a **subtree** (e.g., CN=Users,…).
- `--only-escalation` → show only key rights: **WriteOwner, WriteDACL, GenericAll, GenericWrite**.
- `--hits-only` → hide objects with no matches (reduces visual noise).
- `--size-limit <N>` → cap the number of objects returned by the DC (useful in large OUs).
- `--resolve-sids` → resolve SIDs to names (more readable, slightly slower).
- `--ldaps` → use LDAP over TLS (636) if available (better OPSEC).

> Tip: Always start minimal (surgical) and expand scope only if needed.

---

## 🟢 Low Noise (realistic stealth)

Goal: look like normal LDAP app traffic.  
When: you already have creds and want to see *what that user/group controls*.

Generic template (indent = code sample):
    certipy-acl \
      -u 'user@domain.local' -p 'Password123!' \
      -d domain.local --dc-ip 10.0.0.10 \
      --filter-sid 'S-1-5-21-...' \
      --only-escalation --hits-only --resolve-sids

Example (Judith):
    certipy-acl \
      -u 'judith.mader@certified.htb' -p 'judith09' \
      -d certified.htb --dc-ip 10.129.231.186 \
      --filter-sid 'S-1-5-21-729746778-2675978091-3820388244-1103' \
      --only-escalation --hits-only --resolve-sids

Ultra-surgical (single object):
    certipy-acl \
      -u 'judith.mader@certified.htb' -p 'judith09' \
      -d certified.htb --dc-ip 10.129.231.186 \
      --target-dn 'CN=Management,CN=Users,DC=certified,DC=htb' \
      --filter-sid 'S-1-5-21-729746778-2675978091-3820388244-1103' \
      --only-escalation --hits-only --resolve-sids

Quick WriteOwner check:
    certipy-acl \
      -u 'judith.mader@certified.htb' -p 'judith09' \
      -d certified.htb --dc-ip 10.129.231.186 \
      --target-dn 'CN=Management,CN=Users,DC=certified,DC=htb' \
      --filter-sid 'S-1-5-21-729746778-2675978091-3820388244-1103' \
      --check-writeowner --resolve-sids --hits-only

---

## 🟡 Medium Noise (targeted recon)

Goal: explore a container/OU without mapping the whole domain.  
When: you want pivots in CN=Users, CN=Groups, or a specific OU.

Generic template:
    certipy-acl \
      -u 'user@domain.local' -p 'Password123!' \
      -d domain.local --dc-ip 10.0.0.10 \
      --enum-base 'CN=Users,DC=domain,DC=local' \
      --filter-sid 'S-1-5-21-...' \
      --only-escalation --hits-only --resolve-sids --size-limit 1000

Example (Judith):
    certipy-acl \
      -u 'judith.mader@certified.htb' -p 'judith09' \
      -d certified.htb --dc-ip 10.129.231.186 \
      --enum-base 'CN=Users,DC=certified,DC=htb' \
      --filter-sid 'S-1-5-21-729746778-2675978091-3820388244-1103' \
      --only-escalation --hits-only --resolve-sids --size-limit 1000

---

## 🔴 High Noise (full recon)

Goal: full domain privilege map.  
When: HTB/CTF or authorized audits where noise isn’t a concern.

Generic template:
    certipy-acl \
      -u 'user@domain.local' -p 'Password123!' \
      -d domain.local --dc-ip 10.0.0.10 \
      --resolve-sids

Example (Judith):
    certipy-acl \
      -u 'judith.mader@certified.htb' -p 'judith09' \
      -d certified.htb --dc-ip 10.129.231.186 \
      --resolve-sids

---

## 📊 Comparison Table

| Level | Typical Scope                          | OPSEC  | Typical Use Case                            |
|-----:|-----------------------------------------|--------|---------------------------------------------|
| 🟢 Low  | `--target-dn` / `--filter-sid`           | High   | See what a specific user/object controls    |
| 🟡 Med  | `--enum-base CN=Users` + filters         | Medium | Recon in a specific OU/container            |
| 🔴 High | Root Base DN, no filters (entire domain) | Low    | Massive recon / full domain privilege map   |

---

## 💡 OPSEC Tips

- Encrypt with `--ldaps` (if 636/TLS is available).
- Constrain scope with `--target-dn` or `--enum-base` whenever possible.
- Speed vs readability: `--resolve-sids` improves readability but adds lookups; skip it if you need speed.
- Reduce visual noise: `--only-escalation` + `--hits-only` keeps focus on escalation-relevant rights.
- Control size: `--size-limit` prevents pulling thousands of objects in large OUs.
- Iterate from less to more: start 🟢, escalate to 🟡, and only go 🔴 if necessary.

---

## 📝 Quick Notes

- GenericWrite: commonly inferred from combinations like `WriteProperty`, `Self`, and others. Tools (including BH) surface it to simplify “can I modify this object?” analysis.
- WriteOwner vs WriteDACL: WriteOwner lets you change the **OwnerSID**; WriteDACL lets you edit the **DACL**. Both are powerful (and different) takeover vectors.
- DC compatibility: if a DC doesn’t return `nTSecurityDescriptor` due to policy/controls, try another DC or verify read permissions for that attribute.

---

## 🔙 Back to README

See the project README for install steps, flags, and basic examples.
