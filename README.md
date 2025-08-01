# certipy-acl

🛡️ Custom Certipy ACL module with real LDAP ACE parsing using ldap3 and impacket.

This tool is designed for red teamers and advanced CTF players who want to go beyond BloodHound and enumerate real access rights across Active Directory objects — directly from LDAP.

---

⚠️ Work In Progress

This tool is still under active development.
Some features and output formatting are incomplete or experimental.
Expect updates, improvements, and potential breaking changes.

Your feedback and contributions are highly appreciated to help make this tool better!

---

## 🚀 Usage

python3 -m certipy_tool.certipy acl -u 'user@domain.local' -p 'password123' -target domain.local -dc-ip 10.10.10.10

---

## 📦 Dependencies

Install with pip:

pip install ldap3 impacket

Tested with:

- Python 3.11+
- ldap3 ≥ 2.9
- impacket ≥ 0.11.0

---

## 🐍 Python Environment Setup

To get started, create and activate a virtual environment, then install dependencies:
python3 -m venv certipy-acl-env
source certipy-acl-env/bin/activate
pip install ldap3 impacket
apt install build-essential python3-dev libssl-dev libffi-dev
pip install git+https://github.com/fortra/impacket.git

---


## 🧠 What It Does

- Performs authenticated LDAP bind using NTLM
- Requests and parses nTSecurityDescriptor from all AD objects
- Decodes DACLs into meaningful permissions:
  - GenericAll
  - WriteOwner
  - WriteDACL
  - ResetPassword
  - and more
- Prints ACE types, access masks, and associated SIDs for auditing
- Designed for stealthy enumeration and integration into C2/red team workflows

---

IMPORTANT OUTPUT NOTE 🚨
Currently, the tool’s terminal output does not fully display all detailed ACE information such as WriteOwner and GenericAll entries. This limitation is known and actively being worked on.

💾 HEADS UP: The raw output can be quite large and complex, but don’t worry — you can simply copy & paste it into ChatGPT 🤖 or similar AI tools for deeper analysis and to extract critical ACL insights.

Using ChatGPT to parse this data helps reveal permissions that might be truncated or hidden in the terminal view.


## PARSING STRATEGY AND TIPS

When working with large LDAP ACL outputs, feeding the entire raw data to ChatGPT or other tools can be overwhelming.

A practical approach is to **extract and parse ACL blobs only for known or high-value users/groups** (for example, user accounts). This focused data can be easier to analyze and faster to process.

### PROS OF PARSING BY KNOWN USERS’ ACL BLOBS:
- Smaller, more manageable data chunks  
- Faster parsing and clearer insights on critical targets  
- Easier identification of permissions like WriteOwner and GenericAll
- ## Example Raw Output

When querying ACLs from LDAP, the tool retrieves raw security descriptor data like this (hexadecimal):
 <img width="3801" height="916" alt="image" src="https://github.com/user-attachments/assets/7d05b3b3-9549-44ec-a006-2cda2cccfca4" />
 
Due to the complexity and length of this data, it’s difficult to interpret directly in the terminal.  

This raw data is complex and not human-readable directly. However, after decoding and parsing with the tool (and optionally with ChatGPT), you can extract meaningful ACE entries such as:
<img width="644" height="155" alt="image" src="https://github.com/user-attachments/assets/fefb0f27-4016-44f1-8de8-2716c25784ab" />
This output reveals which users or groups have critical permissions like WriteOwner or GenericAll, which are essential for privilege escalation analysis.

---

### Why this matters

This raw hexadecimal data encodes all the Access Control Entries (ACEs) for the object’s ACL, including permissions like `WriteOwner`, `GenericAll`, and others that are critical for privilege escalation analysis.

---

### How to work with it

- Export this raw output to a file  
- Use tools or scripts (or AI like ChatGPT) to parse and decode the hex into human-readable permissions  
- Focus on objects and users of interest to reduce data volume  

This approach helps reveal the actual permissions hidden inside this opaque data.

---

*Screenshot above shows a real raw security descriptor hex blob returned by the tool.*



### CONS TO CONSIDER:
- You may miss ACEs assigned to other objects that affect permissions indirectly (such as nested groups or delegated OUs)  
- Privilege escalation paths sometimes rely on ACLs from less obvious objects  

### RECOMMENDATION:
Start by parsing ACL data for your known targets, then gradually expand the scope to other relevant objects. Combining focused and broader parsing helps avoid missing critical permissions while keeping analysis manageable.

---

Using this strategy, you can incrementally build a comprehensive view of effective permissions without overwhelming your parsing tools or yourself.


Roadmap  
--json output for automation  
SID-to-name resolution (--resolve-sids)  
Object filtering: --only-users, --only-groups  
Export to BloodHound-compatible format  
Modular integration with Shadow Credentials attack chains  

Project Structure

certipy-acl/  
├── certipy_tool/             # Main Python package folder  
│   ├── __init__.py           # Package initializer (can be empty)  
│   ├── __main__.py           # Main CLI entrypoint; parses arguments and runs the tool  
│   ├── auth.py               # Handles LDAP connection and fetching raw ACL data  
│   └── parse_acl.py          # Parses and formats the LDAP ACE data for output  
├── LICENSE                   # License file describing usage terms  
├── README.md                 # Main documentation and usage instructions  
└── .gitignore                # Git ignore rules  

Details

- certipy_tool/__main__.py  
  This is the main script executed when you run the tool via Python’s -m flag. It handles command-line arguments and orchestrates the process.

- certipy_tool/auth.py  
  Connects to the LDAP server using provided credentials, performs the bind, and retrieves the security descriptors (nTSecurityDescriptor) containing ACL information.

- certipy_tool/parse_acl.py  
  Parses the raw ACLs retrieved from LDAP into human-readable ACE entries, filtering for important permissions such as WriteOwner and GenericAll.

- LICENSE  
  Defines how this tool can be used, shared, and contributed to.

- README.md  
  Provides usage instructions, dependencies, roadmap, and author information.

- .gitignore  
  Specifies files and folders for Git to ignore (e.g., virtual environments, caches).

Handling Output and Data Size

LDAP ACL data can be very large depending on the size of the Active Directory environment you are querying.

To help manage this:

- Use filtering flags (planned or implemented) such as --only-writeowner or --only-genericall to reduce noise.

- Redirect output to a file for easier analysis, for example:  
  python3 -m certipy_tool.certipy acl -u user@domain -p pass -target domain.local -dc-ip 10.10.10.10 > acl_output.txt

- JSON output support (planned) will enable automated parsing and integration with other tools.

Important

This tool is currently primitive and designed as a starting point for advanced users.

Contributions to improve filtering, performance, and output formatting are highly welcome.

Feel free to submit issues or pull requests on GitHub.

Suggestions for Use

- Start with smaller scopes or filtered queries to avoid overwhelming output.

- Combine with other enumeration tools for a comprehensive AD security assessment.

- Use output to identify high-value escalation targets such as objects where you have WriteOwner or GenericAll rights.

Important Note About Output and Collaboration

Currently, the tool’s terminal output does not fully display all the detailed ACE information we are most interested in, such as precise WriteOwner and GenericAll entries.

This limitation is known and actively being worked on.

To work around this:

- Users can export the raw tool output and parse it with ChatGPT or other tools for deeper analysis.

- This approach helps reveal the critical ACL data that may be truncated or omitted in standard terminal views.

Why is this public?

I released this tool publicly to encourage collaboration and collective problem solving.

Parsing LDAP ACLs is complex, and improving the tool requires community input.

If you are interested in Active Directory security, please try the tool, share feedback, or contribute fixes.

Together, we can enhance the accuracy, filtering, and usability of this ACL enumeration utility.

Your support will accelerate the development and help all red teamers and CTF players benefit from better ACL insights!

Thank you for your interest and contributions.

Contributing

This project is open-source and in early development.

Contributions are very welcome to help improve:

- Parsing accuracy and completeness  
- Output formatting and readability  
- Performance and filtering capabilities  
- Adding new features like JSON output or BloodHound export  

How to contribute

1. Fork the repository  
2. Create a feature branch (git checkout -b feature/my-feature)  
3. Commit your changes (git commit -m 'Add some feature')  
4. Push to the branch (git push origin feature/my-feature)  
5. Open a Pull Request  

For major changes, please open an issue first to discuss your idea.

Reporting issues

Please use GitHub Issues to report bugs or request features.

Thank you for helping make this tool better!

License  
To be determined — consider MIT, Red Team license, or custom clause.  

Author  
Maintained by @xploitnik  

Built as part of a hands-on journey into Active Directory exploitation, stealth enumeration, and custom red team tooling. Inspired by gaps in existing tools and driven by a mindset to “see the ACLs, not just guess them.”

“Why wait for BloodHound’s next sync cycle...  
when you can see the ACLs right now?”

    
