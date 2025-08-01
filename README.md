🛡️ Custom Certipy ACL module with real LDAP ACE parsing using ldap3 and impacket.

This tool is designed for red teamers and advanced CTF players who want to go beyond BloodHound and enumerate real access rights across Active Directory objects — directly from LDAP.

🛠️ Usage  
python3 -m certipy_tool.certipy \
  acl -u 'user@domain.local' \
  -p 'password123' \
  -target domain.local \
  -dc-ip 10.10.10.10

📦 Dependencies  
Install with pip:  
pip install ldap3 impacket  

Tested with:  
✅ Python 3.11+  
✅ ldap3 ≥ 2.9  
✅ impacket ≥ 0.11.0  

🧠 What It Does  
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

🧬 Roadmap  
--json output for automation  
SID-to-name resolution (--resolve-sids)  
Object filtering: --only-users, --only-groups  
Export to BloodHound-compatible format  
Modular integration with Shadow Credentials attack chains  

📜 License  
To be determined — consider MIT, Red Team license, or custom clause.  

🤖 Author  
Maintained by @xploitnik  

Built as part of a hands-on journey into Active Directory exploitation, stealth enumeration, and custom red team tooling. Inspired by gaps in existing tools and driven by a mindset to “see the ACLs, not just guess them.”

“Why wait for BloodHound’s next sync cycle...  
when you can see the ACLs right now?”

    
