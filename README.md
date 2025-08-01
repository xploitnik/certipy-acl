Custom Certipy ACL module with real LDAP ACE parsing using ldap3 and impacket.

This tool is designed for red teamers and advanced CTF players who want to go beyond BloodHound and enumerate real access rights across Active Directory objects — directly from LDAP.

Usage  
python3 -m certipy_tool.certipy \
  acl -u 'user@domain.local' \
  -p 'password123' \
  -target domain.local \
  -dc-ip 10.10.10.10

Dependencies  
Install with pip:  
pip install ldap3 impacket  

Tested with:  
Python 3.11+  
ldap3 ≥ 2.9  
impacket ≥ 0.11.0  

What It Does  
Performs authenticated LDAP bind using NTLM  
Requests and parses nTSecurityDescriptor from all AD objects  
Decodes DACLs into meaningful permissions:  
GenericAll  
WriteOwner  
WriteDACL  
ResetPassword  
and more  
Prints ACE types, access masks, and associated SIDs for auditing  
Designed for stealthy enumeration and integration into C2/red team workflows  

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


    
