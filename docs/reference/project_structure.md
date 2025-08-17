# Project Structure

This document explains the layout of the certipy-acl tool and what each file and folder is responsible for.

certipy-acl/
├── certipy_tool/             # Main Python package folder
│   ├── __init__.py           # Package initializer (can be empty)
│   ├── __main__.py           # Main CLI entrypoint; parses arguments and runs the tool
│   ├── auth.py               # Handles LDAP connection and fetching raw ACL data
│   └── parse_acl.py          # Parses and formats the LDAP ACE data for output
├── LICENSE                   # License file describing usage terms
├── README.md                 # Main documentation and usage instructions
└── .gitignore                # Git ignore rules

## Details

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

---

## Notes

This project is early-stage and open for contributions. Feel free to explore the source, report issues, and submit pull requests to improve parsing accuracy, output formatting, and filtering features.
