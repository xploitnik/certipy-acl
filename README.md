# Certipy-ACL — Stealthy LDAP ACL enumeration for AD

[![CI](https://github.com/xploitnik/certipy-acl/actions/workflows/ci.yml/badge.svg)](https://github.com/xploitnik/certipy-acl/actions/workflows/ci.yml)

### Background & Purpose

I built **Certipy-ACL** because most options (e.g., BloodHound) ingest the entire AD graph just to tell me what my current account can do. Certipy-ACL takes a quiet, LDAP-first approach: with a single bind it reads real DACLs and maps **SIDs → permissions** for a specific SID/DN/OU, so you can quickly answer **“who can change what?”** without noisy graph crawling.

- **Bind once** → fetches `nTSecurityDescriptor` only where you ask
- **Filter by SID** or **scope by DN/OU** (`--target-dn`, `--enum-base`)
- **Focus on escalation-relevant rights** (WriteOwner, WriteDACL, GenericAll/Write)
- Optional **SID resolution**, **LDAPS (636/TLS)**, and **size limits** for OPSEC


---

## Install

```bash
pip install -e .
# Requires Python 3.8+, ldap3>=2.9, impacket>=0.11.0
```

---
###  How to run

**A) Basic enumeration (broader / noisier)**
```bash
certipy-acl \
  -u 'user@domain.local' -p 'Password' \
  -d domain.local --dc-ip 10.0.0.10 \
  --resolve-sids
```

**B) RECOMMENDED — filter by trustee SID (no --target-dn needed)**
```bash
# Lists ACEs anywhere the trustee matches your SID (stealth-friendly).
certipy-acl \
  -u 'user@domain.local' -p 'Password' \
  -d domain.local --dc-ip 10.0.0.10 \
  --filter-sid 'S-1-5-21-...-RID' \
  --only-escalation --hits-only --resolve-sids
```

**C) Optional: surgical WITH --target-dn (when you DO know the exact DN)**
```bash
certipy-acl \
  -u 'user@domain.local' -p 'Password' \
  -d domain.local --dc-ip 10.0.0.10 \
  --target-dn 'CN=SomeUser,CN=Users,DC=domain,DC=local' \
  --filter-sid 'S-1-5-21-...-RID' \
  --only-escalation --hits-only --resolve-sids
```

More tactics & OPSEC tips: 🛡️ [Setup & Usage Guide](docs/guides/setup_usage_guide.md)


---


## What you’ll see

Filter by trustee SID & target-dn

<a href="docs/images/acl_writeowner_judith_management.png">
  <img src="docs/images/acl_writeowner_judith_management.png" width="475" alt="WriteOwner over Management group">
</a>

<a href="docs/images/acl_Generic_All.png">
  <img src="docs/images/acl_Generic_All.png" width="350" alt="GenericAll example">
</a>

## Choose your stealth level (at a glance)

| Level | Scope | OPSEC | Typical use |
|---:|---|---|---|
| 🟢 Low | Single SID / object | ✅ High | See what a specific user/group controls |
| 🟡 Medium | One OU / container | ⚠️ Medium | Recon in a bounded subtree |
| 🔴 High | Whole domain | ❌ Low | Full privilege map (HTB/CTF or authorized audits) |

More tactics & OPSEC tips: **[🎭 Stealth Playbook](docs/stealth-playbook.md)**

## Docs

- Setup & Usage: `docs/guides/setup_usage_guide.md`  
- Usage Strategy: `docs/guides/usage_strategy.md`  
- 🎭 Stealth Playbook: `docs/stealth-playbook.md`  
- Project Structure: `docs/reference/project_structure.md`  
- Known Issues: `docs/known_issues.md`  
- Case Study (BloodHound vs Certipy-ACL): `docs/case-studies/bloodhound_vs_certipyacl.md`  
- Changelog: `docs/releases/CHANGELOG.md`

---

## Contributing

PRs welcome. Please add/keep a simple test in `tests/` and ensure CI is green.

**License:** MIT  
**Credits:** Thanks to @ly4k (Certipy) for inspiration.









