# ⚙️ Certipy-ACL — Setup & Usage Guide (Flat Version)

## Quickstart & Commands

### 1) Clone
```bash
git clone https://github.com/xploitnik/certipy-acl.git
cd certipy-acl
```

### 2) (Optional) Isolate with a venv
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3) Install (editable; creates the `certipy-acl` command)
```bash
pip install -e .
# Requires: Python 3.8+, ldap3>=2.9, impacket>=0.11.0
```

> Also works as a module:
```bash
python -m certipy_tool --help
```

### 4) Get your SID (use one of these)
```bash
# Windows
whoami /user

# Impacket
lookupsid.py DOMAIN/USER:'Pass'@<DC_IP>
```

### 5) Use the tool

**A) Basic enumeration (broader / noisier)**
```bash
certipy-acl \
  -u 'user@domain.local' -p 'Password' \
  -d domain.local --dc-ip 10.0.0.10 \
  --resolve-sids
```

**B) RECOMMENDED — filter by trustee SID (no --target-dn needed)**
```bash
# Lists ACEs anywhere the trustee matches your SID (stealth-friendly).
certipy-acl \
  -u 'user@domain.local' -p 'Password' \
  -d domain.local --dc-ip 10.0.0.10 \
  --filter-sid 'S-1-5-21-...-RID' \
  --only-escalation --hits-only --resolve-sids
```

**C) Optional: surgical WITH --target-dn (when you DO know the exact DN)**
```bash
certipy-acl \
  -u 'user@domain.local' -p 'Password' \
  -d domain.local --dc-ip 10.0.0.10 \
  --target-dn 'CN=SomeUser,CN=Users,DC=domain,DC=local' \
  --filter-sid 'S-1-5-21-...-RID' \
  --only-escalation --hits-only --resolve-sids
```

**D) Bounded recon — target a subtree/OU**
```bash
certipy-acl \
  -u 'user@domain.local' -p 'Password' \
  -d domain.local --dc-ip 10.0.0.10 \
  --enum-base 'CN=Users,DC=domain,DC=local' \
  --filter-sid 'S-1-5-21-...-RID' \
  --only-escalation --hits-only --resolve-sids --size-limit 1000
```

### (Optional) Troubleshooting: OpenSSL 3 / MD4
```bash
# If you hit: "[ERROR] Falló el bind LDAP: unsupported hash type MD4"
cat > ~/.openssl-legacy.cnf <<'EOF'
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
legacy  = legacy_sect
[default_sect]
activate = 1
[legacy_sect]
activate = 1
EOF

OPENSSL_CONF=$HOME/.openssl-legacy.cnf python -m certipy_tool --help
```




