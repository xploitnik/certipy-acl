# 🛠️ Certipy ACL — Stealthy AD Permission Enumeration

💬 This module builds directly on top of Certipy, extending the original `find`, `req`, and `auth` modules by adding stealthy LDAP ACL enumeration — a feature I found missing in most modern toolchains.

I kept the Certipy name to credit the original work by [@ly4k](https://github.com/ly4k) and to ensure consistency for users already familiar with the tool. 👉 This fork is meant to **complement**, not compete.

---

## ⚠️ Work In Progress

This tool is under **active development**. Some features and output formatting are incomplete or experimental. Expect updates, improvements, and potential breaking changes.

Your feedback and contributions are highly appreciated!

---

## 🚀 Example Usage

### 🔹 Basic
```bash
python3 -m certipy_tool \
  -u 'user@domain.local' \
  -p 'password123' \
  -target domain.local \
  -dc-ip 10.10.10.10
```

### 🔹 With SID resolution
```bash
python3 -m certipy_tool \
  -u 'user@domain.local' \
  -p 'password123' \
  -target domain.local \
  -dc-ip 10.10.10.10 \
  --resolve-sids
```

### 🔹 With filtering options
```bash
python3 -m certipy_tool \
  --filter-sid S-1-5-21-1111-2222-3333-4444 \
  --only-users \
  --resolve-sids \
  -u 'user@domain.local' \
  -p 'password123' \
  -target domain.local \
  -dc-ip 10.10.10.10
```

---

## 💾 Save Output

You can redirect the output to a file:
```bash
python3 -m certipy_tool \
  ...your args... \
  > acls.txt
```

Then open `acls.txt` or paste it into ChatGPT for analysis.

---

## 🧩 Extensions and Filtering

- `--resolve-sids`: Show human-readable names instead of raw SIDs  
- `--filter-sid <SID>`: Show only ACEs that match the current SID  
- `--only-users`: Limit results to ACEs on user objects (e.g., CN=Users)

---

## 🧠 Real ACL Enumeration — Not Inferred

This tool extracts and decodes **real ACEs from real DACLs**, not inferred paths. That includes:

✅ `WriteOwner`  
✅ `WriteDACL`  
✅ `GenericAll`  
✅ `GenericWrite`

🧠 Think of it as a **sniper**, not a net.  
If you need simulation and graphing, use BloodHound.  
If you want **real rights backed by LDAP**, this tool is your best ally.

---

## ⚠️ What This Tool Does Not Do — by Design

Certipy-ACL is focused on **stealthy and accurate LDAP enumeration**.

To maintain this low footprint, the tool **does not simulate or infer Active Directory privileges**, such as:

- 🔄 `ForceChangePassword`  
- 👥 `AddMember` (Group Membership Modification)  
- 🪪 `WriteSPN`, `WriteUserAccountControl`  
- 🧠 Any **graph-based** or **transitive relationship** prediction  

Those types of analysis require:

- ❌ Scanning *all* domain objects  
- ❌ Querying sensitive attributes (`userAccountControl`, `memberOf`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, etc.)  
- ❌ Heuristics and cross-object correlation  

👉 This tool avoids all that by **only parsing what LDAP explicitly returns** — and only when you're authorized to see it.

---

## 🧱 Known Limitation: No ReadControl = No ACEs

In Active Directory, to view an object’s DACL (permissions), your user must have the `ReadControl` right.

If your current user **does not have ReadControl** on the object, **LDAP will return nothing**, even if:

- You have powerful rights (`WriteOwner`, `GenericAll`, etc.)
- The ACEs are clearly defined
- You’re allowed to modify the object

📦 Output will say:
```text
[!] No DACL or ACEs present
```

This is **not a bug**. It’s LDAP doing its job.

---

## 🧪 Why ChatGPT *Can* Read Permissions

If you paste the **raw output** into ChatGPT, it can decode the ACEs **because you already have the data**.

💡 Analogy:  
> You have a locked garage. LDAP decides whether to give you a window.  
> ChatGPT can read the car inside — **if you hand it a photo**.  

---

## 🧠 Prompt Examples for ChatGPT

Paste your output and ask one of the following:

### 🔹 Filtered (just your user)
> Can you analyze this Certipy ACL output and tell me which ACEs belong to my current user with SID `S-1-5-...`? Highlight any objects where this SID appears and what rights are granted (like WriteOwner or GenericAll).

### 🔹 Unfiltered (see all ACEs)
> Can you analyze this Certipy ACL output and list all ACEs found for every object? Show me the object, SID, ACE type, and what rights are granted. Don’t filter anything.

---

## 📦 Dependencies

```bash
pip install ldap3 impacket pyasn1 pyasn1-modules
```

Tested with:

- Python 3.11+
- `ldap3 ≥ 2.9`
- `impacket ≥ 0.11.0`

---

## 🗂 Project Structure

```
certipy-acl/
├── certipy_tool/
│   ├── __main__.py           # CLI entrypoint
│   ├── auth.py               # LDAP logic + SID resolution
│   ├── parse_acl.py          # ACE parsing logic
│   └── __init__.py
├── README.md
├── .gitignore
└── LICENSE
```

---

## 🛠️ Setup Instructions

```bash
python3 -m venv certipy-acl-env
source certipy-acl-env/bin/activate
pip install ldap3 impacket pyasn1 pyasn1-modules
```

If needed:
```bash
mkdir certipy_tool
mv *.py certipy_tool/
```

---

## 📋 Sample Output

### ✅ Without `--resolve-sids`
```
[ACE] Type: ACCESS_ALLOWED, Mask: 0x80000, SID: S-1-5-21-...
  [+] WriteOwner
```

### ✅ With `--resolve-sids`
```
[ACE] Type: ACCESS_ALLOWED, Mask: 0x80000, SID: CN=Management
  [+] WriteOwner
```

---

## 📣 Why It Matters

Understanding real delegated rights is key for:

- 🔐 Shadow Credentials (ESC8)
- 🪝 Privilege escalation via WriteOwner / GenericAll
- 🕵️ Backdoor and beacon placement
- 🧼 Blue team audits and hardening

---

## 🤝 Contributing

PRs, ideas, and bug reports welcome!

1. Fork this repo  
2. Create a feature branch  
3. Make changes and commit  
4. Push and open a pull request

---

## 📬 License & Author

**Maintainer**: [@xploitnik](https://github.com/xploitnik)  
**License**: MIT

> *“Why wait for BloodHound’s next sync cycle...  
> when you can see the ACLs right now?”*





