# 🛠️ Certipy ACL — Stealthy AD Permission Enumeration

💬 This module builds directly on top of Certipy, extending the original `find`, `req`, and `auth` modules by adding stealthy LDAP ACL enumeration — a feature I found missing in most modern toolchains.

I kept the Certipy name to credit the original work by [@ly4k](https://github.com/ly4k) and to ensure consistency for users already familiar with the tool. This fork is meant to complement, not compete.

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)


---

⚠️ Work In Progress

This tool is still under active development.  
Some features and output formatting are incomplete or experimental.  
Expect updates, improvements, and potential breaking changes.

Your feedback and contributions are highly appreciated to help make this tool better!

---

## 🚀 Example Usage

```bash
# Basic
python3 -m certipy_tool.certipy acl \
  -u 'user@domain.local' \
  -p 'password123' \
  -target domain.local \
  -dc-ip 10.10.10.10

# With SID resolution
python3 -m certipy_tool.certipy acl \
  -u 'user@domain.local' \
  -p 'password123' \
  -target domain.local \
  -dc-ip 10.10.10.10 \
  --resolve-sids
```

---

## 💾 Save Output

You can redirect the output to a file for further analysis or to preserve results across machine resets:

```bash
python3 -m certipy_tool.certipy acl \
  -u 'user@domain.local' \
  -p 'password123' \
  -target domain.local \
  -dc-ip 10.10.10.10 \
  --resolve-sids > output.txt
```

Then open `output.txt` or feed it directly to ChatGPT or your parsing tools for deeper analysis!

---

## 📦 Dependencies

Install with pip:

```bash
pip install ldap3 impacket pyasn1 pyasn1-modules
```

Tested with:

- Python 3.11+
- ldap3 ≥ 2.9
- impacket ≥ 0.11.0

---

## 🧠 What It Does

- Performs authenticated LDAP bind using NTLM
- Requests and parses `nTSecurityDescriptor` from AD objects
- Decodes DACLs into meaningful permissions:
  - GenericAll
  - WriteOwner
  - WriteDACL
  - ResetPassword
  - and more
- Optional SID resolution (`--resolve-sids`) to show human-readable names
- Designed for stealthy enumeration and red team workflows

---

## 📋 Sample Output (With and Without `--resolve-sids`)

✅ **Without `--resolve-sids`**
```
[ACE] Type: ACCESS_ALLOWED, Mask: 0x80000, SID: S-1-5-21-...
  [+] WriteOwner
```

✅ **With `--resolve-sids`**
```
[ACE] Type: ACCESS_ALLOWED, Mask: 0x80000, SID: Management
  [+] WriteOwner
```
<img width="1924" height="580" alt="image" src="https://github.com/user-attachments/assets/1aeeacd7-4287-4d30-8630-1b484509853d" />

---

## 🧪 Parsing Tips & Strategy

Due to the volume of LDAP data, raw ACLs may be hard to interpret directly.  
Instead:

- Focus on **high-value objects** (e.g., user accounts, groups like "Management")
- Use `--resolve-sids` to instantly decode critical SIDs
- Use `>` to export for parsing in ChatGPT or tools
- Search for keywords like `WriteOwner`, `GenericAll`, `ResetPassword`

---

## Project Structure

```
certipy-acl/
├── certipy_tool/
│   ├── __main__.py           # Main CLI entrypoint
│   ├── auth.py               # LDAP logic & SID resolution
│   └── parse_acl.py          # ACE parsing logic
├── README.md
├── LICENSE
└── .gitignore
```

---

## 🛠️ Setup Instructions

### Create Python Virtual Environment

```bash
python3 -m venv certipy-acl-env
source certipy-acl-env/bin/activate
```

### Install Dependencies

```bash
pip install ldap3 impacket pyasn1 pyasn1-modules
```

---

## 🧱 Fix Folder Structure (One-Time Setup)

If your files are not inside a `certipy_tool/` folder:

```bash
mkdir certipy_tool
mv *.py certipy_tool/
```

---

## 🔭 Roadmap

- [x] Real LDAP ACL parsing (Done)
- [x] SID resolution via `--resolve-sids` (Done)
- [ ] Output to JSON
- [ ] Filter flags: `--only-writeowner`, `--only-users`, `--only-groups`
- [ ] BloodHound-compatible output
- [ ] Stealth improvements for red team operations

---

## 🤝 Contributing

Contributions welcome!

### How to Contribute

1. Fork this repo  
2. Create a branch: `git checkout -b feature/my-feature`  
3. Commit changes: `git commit -m "Add feature"`  
4. Push: `git push origin feature/my-feature`  
5. Open a pull request

---

## 📣 Why this matters

Knowing who has rights over what in AD is key to understanding escalation paths, persistence opportunities, and misconfigurations — especially for:

- Shadow Credentials (ESC8)
- ACL abuse (WriteOwner, WriteDACL, GenericAll)
- User-to-user privilege escalation
- Backdoor and beacon placements

---

## 📬 License & Author

**Maintainer:** [@xploitnik](https://github.com/xploitnik)  
**License:** MIT *(or custom Red Team license — TBD)*

> “Why wait for BloodHound’s next sync cycle...  
> when you can **see the ACLs right now**?”


