[![CI](https://github.com/xploitnik/certipy-acl/actions/workflows/ci.yml/badge.svg)](https://github.com/xploitnik/certipy-acl/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python\&logoColor=white)
![ldap3](https://img.shields.io/badge/ldap3-%E2%89%A52.9-blue)
![impacket](https://img.shields.io/badge/impacket-%E2%89%A50.11.0-blueviolet)
![License](https://img.shields.io/badge/License-MIT-green)

# 🔐 Certipy-ACL

**Certipy-acl is a focused, LDAP-first tool for enumerating Active Directory ACLs. It minimizes noisy attribute pulls by reading only nTSecurityDescriptor for the scope you select, surfaces real ACEs and DACLs, and highlights likely privilege-escalation edges (WriteOwner, WriteDacl, GenericAll/Write, AddSelf). Designed for both red-team triage and blue-team analysis, it supports NTLM or Kerberos auth, LDAPS/StartTLS, SID resolution, BloodHound-compatible export, and an --extended-rights mode to reveal control-access and other object-specific rights.

---

## ✨ Why Certipy-ACL?

* 🔎 **LDAP-first & quiet** — fetches only `nTSecurityDescriptor` for the scope you provide
* 🎯 **Focused scanning** — filter by trustee SID or limit to a DN/OU
* ⛑️ **Escalation-centric** — surfaces `WriteOwner`, `WriteDACL`, `GenericAll`/`GenericWrite`, and `AddSelf` (BloodHound-compatible)
* 🔐 **Dual auth** — `--auth ntlm` **or** `--auth kerberos` (SASL/GSSAPI with your ccache)
* 🧩 Extras — SID resolution, LDAPS / StartTLS, size limits, and bulk SID input (`--sid-file`)

---

## 🚀 Quick install

Prefer Kerberos for OPSEC (avoids passwords in shell history).

```bash
# dev / editable install
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Debian/Ubuntu system deps (example)
sudo apt update
sudo apt install -y python3-dev build-essential python3-gssapi libsasl2-modules-gssapi-mit krb5-user
python3 -m pip install -r requirements.txt
```

> If `gssapi` fails, install `libkrb5-dev` and `python3-dev` before `pip install gssapi`.

---

## ⚙️ CLI Usage

Run `certipy-acl -h` for the full argument reference.  Common workflows below.

### Global scan (default)

```bash
certipy-acl --auth kerberos \
  -d "DOMAIN.LOCAL" --dc-ip 10.0.0.1 \
  --resolve-sids --only-escalation --verbose
```

> TIP: Omitting `--filter-sid`, `--sid-file`, and `--target-dn` will scan the entire domain. Full-domain scans can be heavy — prefer scoping with `--target-dn` or `--size-limit`.

### NTLM (lab-only)

```bash
certipy-acl --auth ntlm \
  -u "USER@DOMAIN.LOCAL" -p "P@ssw0rd" -d "DOMAIN.LOCAL" --dc-ip 10.0.0.1 \
  --resolve-sids --only-escalation
```

**Warning:** NTLM on CLI stores passwords in shell history — use only in disposable lab environments.

### Kerberos (recommended)

```bash
kinit user@DOMAIN.LOCAL
certipy-acl --auth kerberos -d "DOMAIN.LOCAL" --dc-ip 10.0.0.1 --resolve-sids
```

### Scope to an OU / DN

```bash
certipy-acl --target-dn "OU=Finance,DC=domain,DC=local" --only-escalation
```

### Filter by trustee SID(s)

Single SID:

```bash
certipy-acl --filter-sid "S-1-5-21-..." --only-escalation --resolve-sids
```

Bulk SIDs from file:

```bash
certipy-acl --sid-file ./sids.txt --only-escalation
```

### LDAPS / StartTLS

```bash
certipy-acl --ldaps --auth kerberos -d DOMAIN.LOCAL --dc-ip 10.0.0.1
```

### Output

* Console table (default)
* JSON / BloodHound export: `--output json --bloodhound`
* CSV: `--output csv`

---

## 🔎 Escalation edges (what we flag)

We highlight ACEs granting rights that commonly lead to privilege escalation:

* `WriteOwner` — take ownership
* `WriteDacl` — change object DACLs
* `GenericAll` / `GenericWrite` — full or write-level control
* `AddSelf` / `SELF` semantics — allow principals to add themselves to groups

These are prioritized when using `--only-escalation` and annotated in exports.

### ➕ `--extended-rights`

Use `--extended-rights` to include additional ACLs that may be relevant for more nuanced escalation paths. When enabled, Certipy-ACL will also flag:

* Object-specific extended rights (e.g., `ResetPassword`, `AllowedToDelegate`) where present
* `ControlAccess` entries such as `ForceChangePassword` and other named control-access rights
* Permissions that are commonly skipped in quick scans but can enable indirect escalation (e.g., `DeleteChild`, other `ControlAccess` entries)

When the tool detects a `ControlAccess` ACE in its default run, it will surface a short clue suggesting re-running with `--extended-rights` (for example: `ControlAccess detected (e.g. ForceChangePassword) — re-run with --extended-rights to expand control-access rights`).

`--extended-rights` is intended for deeper investigations; it increases the amount of ACL data collected and may return more false-positive edges, so pair it with `--filter-sid` or `--target-dn` when possible.

---

## 🛡️ OPSEC & Safety

* Avoid using NTLM with real credentials in persistent shells.
* Scope scans (DN, SID filters, size limits) to reduce impact.
* Use Kerberos and a ccache for cleaner auth.

---

## 🧪 Tests & CI

Run tests locally with `pytest -q`. CI is configured via GitHub Actions (`.github/workflows/ci.yml`).

---

## 📂 Project Structure

```
.
├── src/certipy_tool/     # Core tool code (parsers, auth, main CLI)
├── tests/                # Unit and integration tests
├── docs/                 # Extra documentation and guides
├── .github/              # CI workflows and templates
├── README.md             # Project overview (this file)
├── pyproject.toml        # Build & dependency config
├── LICENSE               # MIT license
├── CONTRIBUTING.md       # Contribution guidelines
```

> For deeper details on modules inside `src/certipy_tool/`, see the `docs/` folder.

---

## 🧰 Development

* Formatting: `black`
* Linting: `ruff`
* Use virtualenv and `pip install -e .` for development.

---

## 🤝 Contributing

1. Open an issue describing the bug or feature
2. Fork the repo and create a focused branch
3. Add tests for new behavior
4. Submit a PR

Please sign any CLA the project requests.

---

## 📝 License

MIT — see `LICENSE`.

---

## 🔖 Changelog (high level)

* v0.1.0 — initial private alpha
* v0.2.0 — `--sid-file`, BloodHound export, Kerberos improvements
* v0.3.0 — LDAPS / StartTLS support, improved filtering

---

Maintainer: xploitnik
Repository: [https://github.com/xploitnik/certipy-acl](https://github.com/xploitnik/certipy-acl)

---










