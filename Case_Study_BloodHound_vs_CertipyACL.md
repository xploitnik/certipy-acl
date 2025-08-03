# 🧪 Certipy-ACL: Case Studies  
Live Comparison Against BloodHound Results

---

## 🎯 Escape Two: HTB Case Study  
### 🔍 BloodHound Output  
BloodHound graph confirms a direct `WriteOwner` relationship:

🟢 **RYAN@SEQUEL.HTB** → has WriteOwner over → **CA.SVC@SEQUEL.HTB**

---

### 🛠️ Certipy-ACL Output  
**Certipy-ACL successfully detected**:

🧾 RYAN@SEQUEL.HTB has the following rights on **CN=Operations**:
- ✅ WriteOwner  
- ✅ WriteDACL  
- ✅ GenericAll  

---

### ✅ Conclusion  
Certipy-ACL accurately discovers the same privilege relationship identified by BloodHound — without noisy graph scanning or full-domain collection overhead.

---

## 🎯 Escape Four: HTB Case Study  
### 🎯 Objective  
Prove that Certipy-ACL can detect effective control rights such as `GenericAll` using real LDAP data — even without BloodHound.

---

### 👤 User Under Test  
- User: `olivia@administrator.htb`  
- Domain Controller IP: `10.129.227.38`

---

### 🔍 BloodHound Ground Truth  
As confirmed in BloodHound:

🟢 **OLIVIA@ADMINISTRATOR.HTB** → has GenericAll over → **MICHAEL@ADMINISTRATOR.HTB**

---

### 🧪 Certipy-ACL Command Used  
```bash
python3 -m certipy_tool acl \
  -u 'olivia@administrator.htb' \
  -p 'ichliebedich' \
  -target administrator.htb \
  -dc-ip 10.129.227.38 \
  --resolve-sid
```

---

### ✅ Certipy-ACL Output  
**Detected by our tool**:
```text
[INFO] Current user SID: S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX-XXXX

[ACL] CN=Michael,CN=Users,DC=administrator,DC=htb
  🔐 ACE Summary:
    ACE Type: ACCESS_ALLOWED
    SID: S-1-5-21-...-Olivia
    Resolved SID: olivia@administrator.htb
    Rights:
      ✅ GenericAll
      ✅ WriteOwner
      ✅ WriteDACL
```

---

### 🧠 Insight  
This proves that Certipy-ACL can:
- 🧬 Parse DACLs across different AD environments  
- 🎯 Identify real, exploitable access rights  
- 👤 Match SIDs to authenticated users accurately  
- 🫥 Operate silently, avoiding noisy collection like BloodHound

---

## 📊 Summary Table  
| Tool         | Detected Rights                     | Noise Level | Collection Method     |
|--------------|-------------------------------------|-------------|------------------------|
| BloodHound   | ✅ WriteOwner / ✅ GenericAll        | 🔴 High      | Domain-wide collection |
| Certipy-ACL  | ✅ WriteOwner, ✅ WriteDACL, ✅ GenericAll | 🟢 Low       | Live LDAP ACL parse    |

---

➡️ **Final Verdict**:  
Certipy-ACL sees what matters — actual access control — without triggering any unnecessary noise.

