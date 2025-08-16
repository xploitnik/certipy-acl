# ⚙️ Certipy ACL Tool — Setup & Usage Guide (Flat Version)

This tool silently binds to LDAP and parses Active Directory security descriptors (DACLs), decoding Access Control Entries (ACEs) for privilege escalation insights. Unlike older versions, ACEs are now printed directly in the terminal — no more hidden output.

---

## 1. Clone the Repository

git clone https://github.com/xploitnik/certipy-acl.git  
cd certipy-acl  

---

## 2. Create & Activate a Python Virtual Environment

We strongly recommend isolating your environment.

python3 -m venv certipy-acl-env  
source certipy-acl-env/bin/activate  

Then install the required dependencies:

pip install ldap3 impacket pyasn1 pyasn1-modules  

---

## 3. Fix the Folder Structure (One-Time Setup)

The Python files must live inside a `certipy_tool/` package folder.

mkdir certipy_tool  
mv *.py certipy_tool/  
touch certipy_tool/__init__.py  

Final structure should now look like:

certipy-acl/  
├── certipy_tool/  
│   ├── auth.py  
│   ├── parse_acl.py  
│   ├── __main__.py  
│   └── __init__.py  
├── README.md  
├── LICENSE  

---

## 4. Navigate to the Correct Path Before Running

cd /home/xpl0itnik/certipy/certipy-acl  

---

## 5. Run the Tool

### Show Help
python3 -m certipy_tool  
python3 -m certipy_tool --help  

---

### Example Usage (Certified HTB)

python3 -m certipy_tool \
  -u 'judith.mader@certified.htb' \
  -p 'judith09' \
  -d certified.htb \
  --dc-ip 10.129.231.186 \
  --resolve-sids  

---

### Global Usage

python3 -m certipy_tool \
  -u '<user>@<domain>' \
  -p '<password>' \
  -d <fqdn or domain name> \
  --dc-ip <domain controller IP>  

---

## 🔑 What It Does

This command binds to LDAP, retrieves security descriptors for directory objects, and decodes DACLs to reveal effective escalation rights:

- WriteOwner  
- WriteDACL  
- GenericWrite  
- GenericAll  

---

## 🧩 Optional Extensions & Filtering

You can extend the output control using the following flags:

- `--resolve-sids`  
Resolves raw SIDs into human-readable names using LDAP lookups.

- `--filter-sid <SID>`  
Only shows ACEs that match this specific SID (e.g., your current user SID).  
Example:  
--filter-sid S-1-5-21-729746778-2675978091-3820388244-1103  

- `--target-dn <DN>`  
Limit search to a single object or subtree. Useful to focus on specific groups/users.  
Example:  
--target-dn 'CN=Management,CN=Users,DC=certified,DC=htb'  

- `--hits-only`  
Show only ACEs that match escalation-relevant rights (WriteOwner, WriteDACL, GenericAll, GenericWrite).

- `--only-escalation`  
Alias for `--hits-only`.  

- `--ldaps`  
Force LDAPS instead of plain LDAP.  

- `--no-bh-compat`  
Disable GenericWrite inference (BloodHound compatibility mode off).  

- `--size-limit <N>`  
Only parse the first N objects (performance testing).  

---

## 💡 Recommended Workflow

1. First run with your current user SID filter:  
   --filter-sid <yourSID> --hits-only --resolve-sids  

2. If nothing useful appears, expand search with:  
   --target-dn <OU or CN>  

3. Compare results with and without `--hits-only` to check noise vs. stealth escalation paths.  

---

## 🧠 Use Cases

This tool is built for:  
- 🔴 Red teamers seeking **silent enumeration**  
- 🧩 CTF players avoiding noisy tools like BloodHound  
- 🕵️ Researchers investigating shadow credentials or object takeovers  

Created by **@xploitnik** — powered by **ldap3**, **impacket**, and a custom Certipy ACL module.  


