# 🛠️ Certipy ACL — Stealthy AD Permission Enumeration

💬 This module builds directly on top of Certipy, extending the original `find`, `req`, and `auth` modules by adding stealthy LDAP ACL enumeration — a feature I found missing in most modern toolchains.

I kept the Certipy name to credit the original work by @ly4k and to ensure consistency for users already familiar with the tool. 👉 This fork is meant to complement, not compete.

---

## ⚠️ Work In Progress

This tool is under active development. Some features and output formatting are incomplete or experimental. Expect updates, improvements, and potential breaking changes.

Your feedback and contributions are highly appreciated!

---

## 🚀 Example Usage

### 🔹 Basic
python3 -m certipy_tool \
  -u '<user@domain>' \
  -p 'Password' \
  -d <domain_fqdn> \
  --dc-ip <dc_ip> \
  --target-dn '<distinguished_name>' \
  [--filter-sid '<sid>'] [--resolve-sids] [--hits-only] [--ldaps] [--verbose]

# Example Certified.htb
```
python3 -m certipy_tool \
  -u 'judith.mader@certified.htb' \
  -p 'judith09' \
  -d certified.htb \
  --dc-ip 10.129.231.186 \
  --resolve-sids
```
### 🔹 With filtering options
# Example 1: without a Target Object (--target-dn)
```
python3 -m certipy_tool \
  -u 'judith.mader@certified.htb' \
  -p 'judith09' \
  -d certified.htb \
  --dc-ip 10.129.231.186 \
  --filter-sid 'S-1-5-21-729746778-2675978091-3820388244-1103' \
  --resolve-sids \
  --hits-only
```

# Example 2: with Target Object
```
python3 -m certipy_tool \
  -u 'judith.mader@certified.htb' \
  -p 'judith09' \
  -d certified.htb \
  --dc-ip 10.129.231.186 \
  --target-dn 'CN=Management,CN=Users,DC=certified,DC=htb' \
  --filter-sid 'S-1-5-21-729746778-2675978091-3820388244-1103' \
  --resolve-sids \
  --hits-only
```

NOTE: If you are checking RID 1104, update --filter-sid to end in -1104 and change --target-dn accordingly. Always quote DNs and SIDs.

---

## 🧩 Extensions and Filtering

Flags (quick ref):
- --target-dn — limit search to a DN/subtree (quote it).
- --filter-sid — show ACEs where trustee == SID (quote it).
- --size-limit — process only first N objects (perf).
- --check-writeowner — boolean check for WriteOwner.
- --only-escalation / --hits-only — show only escalation-relevant rights.
- --resolve-sids — resolve SIDs to names via LDAP.
- --ldaps — use LDAPS.
- --no-bh-compat — disable “GenericWrite (derived)” inference.
- --verbose — extra logs.

---

## 🧠 Real ACL Enumeration — Not Inferred

This tool extracts and decodes real ACEs from real DACLs, not inferred paths. That includes:

✅ WriteOwner  
✅ WriteDACL  
✅ GenericAll  
✅ GenericWrite

Think of it as a sniper, not a net.  
If you need simulation and graphing, use BloodHound.  
If you want real rights backed by LDAP, this tool is your best ally.

---

## ✨ New Improvements

- ACEs are now printed directly in the terminal during live bind.  
- No silent skipping: if your SID appears but has no key rights, you still see the ACE and a message `[!] No matching rights found.`  
- Full support for surgical flags like --filter-sid and --target-dn.  
- Easier to spot stealthy vs noisy escalation options at a glance.

---

## ⚠️ What This Tool Does Not Do — by Design

Certipy-ACL is focused on stealthy and accurate LDAP enumeration.

To maintain this low footprint, the tool does not simulate or infer Active Directory privileges, such as:

- ForceChangePassword  
- AddMember  
- WriteSPN, WriteUserAccountControl  
- Any graph-based or transitive prediction  

👉 This tool avoids all that by only parsing what LDAP explicitly returns — and only when you're authorized to see it.

---

## 🧱 Known Limitation: No ReadControl = No ACEs

If your user lacks ReadControl on an object, LDAP will return no ACEs.  
This is not a bug, it’s expected behavior.

Output will say:
[!] No DACL or ACEs present

---

## 📦 Dependencies

pip install ldap3 impacket pyasn1 pyasn1-modules

Tested with:
- Python 3.11+
- ldap3 ≥ 2.9
- impacket ≥ 0.11.0

---

## 🗂 Project Structure

certipy-acl/  
├── certipy_tool/  
│   ├── __main__.py           # CLI entrypoint  
│   ├── auth.py               # LDAP logic + SID resolution  
│   ├── parse_acl.py          # ACE parsing logic  
│   └── __init__.py  
├── README.md  
├── .gitignore  
└── LICENSE  

---

## 🛠️ Setup Instructions

python3 -m venv certipy-acl-env  
source certipy-acl-env/bin/activate  
pip install ldap3 impacket pyasn1 pyasn1-modules  

---

## 📣 Why It Matters

Understanding real delegated rights is key for:
- Shadow Credentials (ESC8)  
- Privilege escalation via WriteOwner / GenericAll  
- Backdoor and beacon placement  
- Blue team audits and hardening  

---

## ⚖️ Legal and Ethical Use

This project is intended for educational, research, and defensive purposes only.  
Do not use it on systems without explicit written authorization.

Unauthorized use of this tool against networks you do not own or operate may violate local, state, and federal laws.  
The maintainer is not responsible for any misuse or damages caused.

👉 Use responsibly. Always test in controlled labs, CTFs, or authorized penetration tests.

---

## 🤝 Contributing

PRs, ideas, and bug reports welcome!

1. Fork this repo  
2. Create a feature branch  
3. Make changes and commit  
4. Push and open a pull request  

---

## 📬 License & Author

Maintainer: @xploitnik  
License: MIT

“Why wait for BloodHound’s next sync cycle... when you can see the ACLs right now?”






