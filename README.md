# Certipy-ACL · Stealthy LDAP ACL enumeration for AD

[![CI](https://github.com/xploitnik/certipy-acl/actions/workflows/ci.yml/badge.svg)](https://github.com/xploitnik/certipy-acl/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![ldap3](https://img.shields.io/badge/ldap3-%E2%89%A52.9-blue)
![impacket](https://img.shields.io/badge/impacket-%E2%89%A50.11.0-blueviolet)
![License](https://img.shields.io/badge/License-MIT-green)

## 🔐 Certipy-ACL

Stealthy LDAP ACL mapper for Active Directory.  
Bind once, enumerate real ACEs/DACLs, and highlight escalation paths — fast and quiet. 🕵️


---

## ✨ Why Certipy-ACL?

- 🔎 **LDAP-first & quiet** — pulls only `nTSecurityDescriptor` where you scope it  
- 🎯 **Focus** — filter by **trustee SID** or limit to a **DN/OU**  
- ⛑️ **Escalation-centric** — highlights WriteOwner, WriteDACL, GenericAll/Write, and Self (AddSelf) (BloodHound-compatible)  
- 🔐 **Dual auth** — `--auth ntlm` **or** `--auth kerberos` (SASL/GSSAPI with your ccache)  
- 🧩 Extras — SID resolution, LDAPS / StartTLS, size limits, and **bulk SID** input (`--sid-file`)

---

## 🚀 Install & Example Usage

> Small examples are shown inline. Expand the full copy/paste block if you want the entire install + examples snippet.  
> 🔒 OPSEC tip: prefer **Kerberos** where possible (no passwords in shell history).

### 🧩 Quick install (uncomment what you need)
```bash
# pip install -e .
# sudo apt update && sudo apt install -y python3-gssapi libsasl2-modules-gssapi-mit krb5-user
# sudo apt install -y python3-dev libkrb5-dev build-essential && python3 -m pip install gssapi
```











