Release v1.0.0 - Initial Public Release 🚀
Date: (7/31/2025)

Overview
I am excited to announce the initial public release of certipy-acl — a custom Certipy ACL enumeration module with real LDAP ACE parsing using ldap3 and impacket.

This tool is designed for red teamers and advanced CTF players who want to gain deeper insights into Active Directory permissions beyond traditional tools like BloodHound.

Features
Authenticated LDAP bind with NTLM support

Fetches and parses nTSecurityDescriptor attributes to enumerate ACLs directly from LDAP

Decodes detailed Access Control Entries (ACEs) including critical rights such as WriteOwner and GenericAll

Outputs readable permission entries for auditing and privilege escalation analysis

Supports integration into red team workflows and C2 frameworks

Known Limitations
Terminal output currently may not fully display all ACE details; exporting raw output and parsing with ChatGPT or other tools is recommended

The tool is in active development; expect new features and improvements in upcoming releases

Getting Started
Check out the README for installation, usage, and environment setup instructions.

How to Contribute
This is an open-source project and we welcome your contributions! Please submit issues, feature requests, or pull requests on GitHub.

Thank You!
Special thanks to everyone testing and providing feedback. Together we’ll build a powerful and reliable ACL enumeration toolkit.

