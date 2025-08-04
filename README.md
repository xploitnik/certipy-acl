🛠️ Certipy ACL — Stealthy AD Permission Enumeration

💬 This module builds directly on top of Certipy, extending the original find, req, and auth modules by adding stealthy LDAP ACL enumeration — a feature I found missing in most modern toolchains.

I kept the Certipy name to credit the original work by @ly4k and to ensure consistency for users already familiar with the tool. 👉 This fork is meant to complement, not compete.



⚠️ Work In Progress

This tool is still under active development.Some features and output formatting are incomplete or experimental.Expect updates, improvements, and potential breaking changes.

Your feedback and contributions are highly appreciated to help make this tool better!

🚀 Example Usage

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

# With filtering options
python3 -m certipy_tool.certipy acl \
  -u 'user@domain.local' \
  -p 'password123' \
  -target domain.local \
  -dc-ip 10.10.10.10 \
  --resolve-sids \
  --filter-sid S-1-5-21-1111111111-2222222222-3333333333-4444 \
  --only-users

💾 Save Output

You can redirect the output to a file for further analysis or to preserve results across machine resets:

python3 -m certipy_tool.certipy acl \
  -u 'user@domain.local' \
  -p 'password123' \
  -target domain.local \
  -dc-ip 10.10.10.10 \
  --resolve-sids > output.txt

Then open output.txt or feed it directly to ChatGPT or your parsing tools for deeper analysis!

🧩 Extensions and Filtering Options

--resolve-sids: Convert raw SID to usernames/groups using live LDAP queries

--filter-sid <SID>: Show only ACEs that match the current user or specific SID (e.g., low-privileged user only)

--only-users: Limit results to ACEs set on user objects

🧪 Prompt Examples for Analysis

If you're using the saved output with ChatGPT, try these example prompts:

Filter by current user SID:

Can you analyze this Certipy ACL output and tell me which ACEs belong to my current user with SID S-1-5-21-729746778-2675978091-3820388244-1103? Highlight any objects where this SID appears, what rights are granted (like WriteOwner or GenericAll), and ignore anything outside this domain SID or built-in groups.

No filter (full enumeration):

Can you analyze this Certipy ACL output and list all ACEs found for every object? I want to see the full breakdown — show me the object, SID, rights (like WriteOwner or GenericAll), and ACE type. Don’t filter anything.

📦 Dependencies

Install with pip:

pip install ldap3 impacket pyasn1 pyasn1-modules

Tested with:

Python 3.11+

ldap3 ≥ 2.9

impacket ≥ 0.11.0

🧠 What It Does

Performs authenticated LDAP bind using NTLM

Requests and parses nTSecurityDescriptor from AD objects

Decodes DACLs into meaningful permissions:

GenericAll

WriteOwner

WriteDACL

ResetPassword

and more

Optional SID resolution (--resolve-sids) to show human-readable names

Designed for stealthy enumeration and red team workflows

⚠️ What This Tool Does Not Do — by Design

Certipy-ACL is focused on stealthy and accurate LDAP enumeration.To maintain this low footprint, the tool does not attempt to simulate or infer Active Directory privileges like:

🔄 ForceChangePassword

👥 AddMember

🔁 WriteSPN, WriteUserAccountControl

🧠 Any graph-based relationship prediction

These rights require inferring logical relationships (e.g., “User A can change the password of User B”), which demands:

❌ Scanning every object in the domain

❌ Querying attributes like userAccountControl, memberOf, msDS-AllowedToActOnBehalfOfOtherIdentity

❌ Risking detection by blue teams

🧱 That’s not the mission of this tool.

Instead, Certipy-ACL is designed to:

✅ Parse real DACLs and ACEs

✅ Match only what’s explicitly delegated in LDAP

✅ Operate quietly and precisely

✅ Focus on rights that matter for escalation:

WriteOwner

WriteDACL

GenericAll

GenericWrite

🧠 Think of this tool as a sniper, not a net.

If you need simulation or inferred access paths, BloodHound remains the right tool.If you want clean, accurate insight from real delegation — Certipy-ACL is your best ally.

📋 Sample Output (With and Without --resolve-sids)

✅ Without --resolve-sids

[ACE] Type: ACCESS_ALLOWED, Mask: 0x80000, SID: S-1-5-21-...
  [+] WriteOwner

✅ With --resolve-sids

[ACE] Type: ACCESS_ALLOWED, Mask: 0x80000, SID: Management
  [+] WriteOwner

🧪 Parsing Tips & Strategy

Due to the volume of LDAP data, raw ACLs may be hard to interpret directly.Instead:

Focus on high-value objects (e.g., user accounts, groups like "Management")

Use --resolve-sids to instantly decode critical SIDs

Use > to export for parsing in ChatGPT or tools

Search for keywords like WriteOwner, GenericAll, ResetPassword

Project Structure

certipy-acl/
├── certipy_tool/
│   ├── __main__.py           # Main CLI entrypoint
│   ├── auth.py               # LDAP logic & SID resolution
│   ├── parse_acl.py          # ACE parsing logic
│   └── __init__.py           # Marks the folder as a package
├── README.md
├── LICENSE
└── .gitignore

🛠️ Setup Instructions

Create Python Virtual Environment

python3 -m venv certipy-acl-env
source certipy-acl-env/bin/activate

Install Dependencies

pip install ldap3 impacket pyasn1 pyasn1-modules

🧱 Fix Folder Structure (One-Time Setup)

If your files are not inside a certipy_tool/ folder:

mkdir certipy_tool
mv *.py certipy_tool/

🔭 Roadmap



🤝 Contributing

Contributions welcome!

How to Contribute

Fork this repo

Create a branch: git checkout -b feature/my-feature

Commit changes: git commit -m "Add feature"

Push: git push origin feature/my-feature

Open a pull request

📣 Why this matters

Knowing who has rights over what in AD is key to understanding escalation paths, persistence opportunities, and misconfigurations — especially for:

Shadow Credentials (ESC8)

ACL abuse (WriteOwner, WriteDACL, GenericAll)

User-to-user privilege escalation

Backdoor and beacon placements

📬 License & Author

Maintainer: @xploitnikLicense: MIT (or custom Red Team license — TBD)

“Why wait for BloodHound’s next sync cycle...when you can see the ACLs right now?”


