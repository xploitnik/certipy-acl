

    
# 🛡️ Certipy ACL Tool — Setup & Usage Guide

This tool silently binds to LDAP and parses Active Directory security descriptors (DACLs), decoding Access Control Entries (ACEs) for privilege escalation insights.

---

## 1. Clone the Repository

```bash
git clone https://github.com/xploitnik/certipy-acl.git
cd certipy-acl
```

---

## 2. Create & Activate a Python Virtual Environment

We strongly recommend isolating your environment:

```bash
python3 -m venv certipy-acl-env
source certipy-acl-env/bin/activate
```

### Install Dependencies

```bash
pip install ldap3 impacket pyasn1 pyasn1-modules
```

---

## 3. Fix Folder Structure (One-Time Setup)

The Python files must live inside a `certipy_tool/` package folder:

```bash
mkdir certipy_tool
mv *.py certipy_tool/
touch certipy_tool/__init__.py
```

Final structure should look like:

```
certipy-acl/
├── certipy_tool/
│   ├── auth.py
│   ├── parse_acl.py
│   ├── __main__.py
│   └── __init__.py
├── README.md
├── LICENSE
```

---

## 4. Navigate to Correct Directory Before Running

```bash
cd /home/xpl0itnik/certipy/certipy-acl
source certipy-acl-env/bin/activate
```

---

## 5. Run the Tool

### Show Help

```bash
python3 -m certipy_tool ac
python3 -m certipy_tool ac --help
```

---

## 🧪 Example Usage (Certified HTB)

```bash
python3 -m certipy_tool acl \
  -u 'judith.mader@certified.htb' \
  -p 'judith09' \
  -target certified.htb \
  -dc-ip 10.129.231.186
```

---

## 🌐 Global Usage

```bash
python3 -m certipy_tool acl \
  -u '<user>@<domain>' \
  -p '<password>' \
  -target <fqdn or IP> \
  -dc-ip <domain controller IP>
```

This command binds to LDAP, retrieves security descriptors for directory objects, and decodes DACLs to reveal:
- WriteOwner
- WriteDACL
- GenericWrite
- GenericAll

---

## 🧠 What It Does

- Authenticated LDAP bind using NTLM
- Retrieves `nTSecurityDescriptor` from AD objects
- Decodes DACLs for:
  - GenericAll
  - WriteOwner
  - WriteDACL
  - ResetPassword
- Prints ACE types, access masks, and SIDs

---

## ⚠️ Output Notes

> Terminal output may **not show all ACEs** like `WriteOwner` or `GenericAll`.  

To fully decode raw blobs:

- Copy the output and **paste into ChatGPT or CyberChef**
- Use `--resolve-sids` (coming soon) to get readable user/group names
- Export hex blobs to file and analyze manually

---

## 🔍 Parsing Strategy

Instead of parsing all ACLs:

### 🎯 Focus on high-value objects:

- Known users or groups
- Admin accounts
- Management units

### ✅ Pros:
- Smaller outputs
- Faster parsing
- Focus on escalation targets

### ⚠️ Cons:
- Might miss nested group permissions or delegated rights

---

## 🔓 Example Raw Output

Hex returned from LDAP:

```
0100048c000000000000000000000000140000000400140621000000...
```

Decoded output shows:

```text
[ACL] CN=Management,CN=Users,DC=certified,DC=htb
  [ACE] Type: ACCESS_ALLOWED_OBJECT_ACE_TYPE, Mask: 0x80000, SID: S-1-5-21-...
    [+] WriteOwner
```

---

## 🔧 Project Structure

```
certipy-acl/
├── certipy_tool/
│   ├── auth.py
│   ├── parse_acl.py
│   ├── __main__.py
│   └── __init__.py
├── LICENSE
├── README.md
├── .gitignore
```

---

## 📈 Roadmap

- ✅ ACE parsing (WriteOwner, GenericAll, etc.)
- 🔜 `--resolve-sids` flag
- 🔜 Output in JSON
- 🔜 Filters: `--only-users`, `--only-writeowner`, etc.
- 🔜 Shadow credentials integration
- 🔜 BloodHound-compatible export

---

## 🤝 Contributing

1. Fork the repo  
2. Create a feature branch  
3. Commit & push your changes  
4. Open a pull request  
5. Share how it helps!

---

## 📢 Why This Tool?

BloodHound is powerful — but noisy and overkill in some situations.  
This tool is for red teamers, hackers, and CTFers who want:

- 🔇 Stealth
- 🧠 Precision
- 🔍 Real DACL insight

> “Why wait for BloodHound’s next sync cycle...  
> when you can see the ACLs right now?”

---

## 🧑‍💻 Author

Created by [@xploitnik](https://github.com/xploitnik)  
Built during hands-on AD red team training and real-world enumeration challenges.

MIT License (or custom Red Team license — TBD)

---

Happy hacking! 🎯
