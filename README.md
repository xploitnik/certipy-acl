# Certipy-ACL · Stealthy LDAP ACL enumeration for AD

[![CI](https://github.com/xploitnik/certipy-acl/actions/workflows/ci.yml/badge.svg)](https://github.com/xploitnik/certipy-acl/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![ldap3](https://img.shields.io/badge/ldap3-%E2%89%A52.9-blue)
![impacket](https://img.shields.io/badge/impacket-%E2%89%A50.11.0-blueviolet)
![License](https://img.shields.io/badge/License-MIT-green)

> **Quiet by design.** Bind once, read real DACLs, map **SIDs → permissions** fast — no noisy full-graph crawls.

---

## ✨ Why Certipy-ACL?

- 🔎 **LDAP-first & quiet** — pulls only `nTSecurityDescriptor` where you scope it  
- 🎯 **Focus** — filter by **trustee SID** or limit to a **DN/OU**  
- ⛑️ **Escalation-centric** — highlights WriteOwner, WriteDACL, GenericAll/Write (BloodHound-compatible)  
- 🔐 **Dual auth** — `--auth ntlm` **or** `--auth kerberos` (SASL/GSSAPI with your ccache)  
- 🧩 Extras — SID resolution, LDAPS / StartTLS, size limits, and **bulk SID** input (`--sid-file`)

---

## 🚀 Quick links

- [Install & Example Usage (single copy/paste block)](#-install--example-usage-single-copypaste-block)  
- [Flags at a glance](#-flags-at-a-glance)  
- [Screenshots](#-screenshots)  
- [Docs](#-docs)  
- [Contributing](#-contributing)

---

## 🚀 Install & Example Usage (single copy/paste block)

> All install steps and example invocations are included in **one single fenced `bash` block** below. Copy that entire block to run examples / adapt variables.

```bash
#!/usr/bin/env bash
# Single-block: install + NTLM + Kerberos + bulk SID usage examples (edit variables below)
# Paste this entire block as one copy/paste to a terminal (edit variables first)

# ================
# Basic config (edit to match your environment)
# ================
DOMAIN="domain.local"
DC_IP="10.0.0.10"
DC_FQDN="dc.domain.local"        # used for Kerberos SPN matching
SID_FILE="decoded-sids"          # path to your SID list (name,SID or plain SID per line)
CCACHE="/tmp/rr.parker.ccache"   # optional ccache path if you want to use a custom cache

# ================
# 0) Install (Python deps + optional system package for gssapi)
#    (Uncomment the commands you need)
# ================
# pip install -e .
# Debian/Ubuntu (preferred gssapi package):
# sudo apt update && sudo apt install -y python3-gssapi libsasl2-modules-gssapi-mit krb5-user
# If distro package not available, install build deps and pip gssapi:
# sudo apt install -y python3-dev libkrb5-dev build-essential
# python3 -m pip install gssapi

# ================
# 1) NTLM example (password mode)
#    - Legacy/simple; requires username & password on CLI (beware shell history).
#    - Replace USER and PASSWORD placeholders before running.
# ================
echo "=== NTLM example ==="
certipy-acl \
  --auth ntlm \
  -u 'USER@'"${DOMAIN}" -p 'PASSWORD' \
  -d "${DOMAIN}" --dc-ip "${DC_IP}" \
  --resolve-sids \
  --only-escalation \
  --verbose

# ================
# 2) Kerberos example (recommended)
#    - Acquire a TGT first (interactive or via keytab/ccache). No password on CLI.
# ================
echo "=== Kerberos example (kinit + run) ==="

# Option A: interactive kinit (you will be prompted for the password)
# kinit rr.parker@"${DOMAIN}"

# Option B: use a keytab (uncomment and edit path if you have one)
# kinit -k -t /path/to/keytab host/yourhost@"${DOMAIN}"

# Option C: use an existing ccache file (set KRB5CCNAME for this run)
# export KRB5CCNAME="${CCACHE}"

# Example run (assumes you have a valid TGT in your default cache or set KRB5CCNAME)
certipy-acl \
  --auth kerberos \
  -d "${DOMAIN}" \
  --dc-ip "${DC_IP}" \
  --dc-host "${DC_FQDN}" \
  --starttls \
  --resolve-sids \
  --verbose

# ================
# 3) Bulk SID-file run (Kerberos preferred, but works with NTLM too)
#    - SID_FILE should contain lines like:
#        Support-Computer1$  , S-1-5-21-...-1103
#        S-1-5-21-...-1125
#      Blank lines and lines starting with # are ignored.
# ================
echo "=== Bulk SID-file run (Kerberos) ==="
certipy-acl \
  --auth kerberos \
  -d "${DOMAIN}" \
  --dc-ip "${DC_IP}" \
  --dc-host "${DC_FQDN}" \
  --starttls \
  --sid-file "${SID_FILE}" \
  --only-escalation \
  --resolve-sids \
  --verbose

# If you need to use NTLM for bulk:
# certipy-acl --auth ntlm -u 'USER' -p 'PASSWORD' -d "${DOMAIN}" --dc-ip "${DC_IP}" --sid-file "${SID_FILE}" --only-escalation

# ================
# 4) Narrow scope / surgical example (target-dn)
#    - Use when you already know the exact DN to speed up enumeration and improve OPSEC.
# ================
echo "=== Surgical: target a specific DN ==="
certipy-acl \
  --auth kerberos \
  -d "${DOMAIN}" \
  --dc-ip "${DC_IP}" \
  --dc-host "${DC_FQDN}" \
  --target-dn "CN=SomeUser,CN=Users,DC=domain,DC=local" \
  --filter-sid "S-1-5-21-...-RID" \
  --only-escalation \
  --resolve-sids \
  --starttls

# ================
# 5) Helpful notes (displayed after examples)
# ================
cat <<'NOTES'

Helpful notes / OPSEC tips:
- For Kerberos, ensure the DC FQDN you pass with --dc-host matches the SPN (ldap/<fqdn>).
  If the FQDN doesn't resolve to the DC IP, add an /etc/hosts entry:
    sudo bash -c "echo '${DC_IP} ${DC_FQDN}' >> /etc/hosts"

- Acquire a TGT before Kerberos runs:
    kinit rr.parker@DOMAIN.LOCAL
  Or set a custom cache:
    export KRB5CCNAME=/path/to/ccache

- Avoid putting passwords in shell history. Prefer kinit/keytab/ccache for Kerberos or read password from a protected file if required.

- To save output for later review:
    python3 -m certipy_tool [args...] > certipy_results.txt
  or for bulk SID runs:
    python3 -m certipy_tool [args...] --sid-file decoded-sids > sid_bulk_results.txt













