## ⚠️ Before We Start: Why Certipy-ACL Shows Multiple ACE Permissions

🧠 **Why Certipy-ACL Shows Multiple Rights While BloodHound Shows Only One**

### 🔍 BloodHound
- Focuses on **relationship mapping**, not full DACL breakdowns.
- When it shows `GenericAll`, it’s **summarizing** that the user has enough rights to fully control the object.
- It does **not display individual rights** like `WriteOwner`, `WriteDACL`, or `GenericWrite` — even if they’re present.
- 📌 **BloodHound picks the most powerful right** and shows that as a simplified graph edge (e.g., `GenericAll` → full control).

---

### 🔎 Certipy-ACL
- Parses the **raw LDAP DACL bitmask** for every object.
- Lists **every right explicitly granted** to the user.
- If the bitmask includes:
  - `0x02000000` → `GenericWrite`
  - `0x08000000` → `GenericAll`
  - `0x00080000` → `WriteOwner`
  - `0x00040000` → `WriteDACL`

  ...then **all of these will be shown**.

- 📌 This provides **full transparency** and lets red teamers:
  - Understand *exactly* what’s possible
  - Choose the *least noisy* or most *targeted* exploitation path

---

✅ **Certipy-ACL is not just about knowing you can exploit something — it’s about knowing *how* you want to exploit it.**

# 🧪 Certipy-ACL: Case Studies  
Live Comparison Against BloodHound Results

---

## 🎯 Escape Two: HTB Case Study  
### 🔍 BloodHound Output  
BloodHound graph confirms a direct `WriteOwner` relationship:

<img width="523" height="202" alt="image" src="https://github.com/user-attachments/assets/c8e8a6cd-fbda-4ad7-8eb0-7d2a993ee0b4" />

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

## 🎯 Administrator: HTB Case Study  
### 🎯 Objective  
Prove that Certipy-ACL can detect effective control rights such as `GenericAll` using real LDAP data — even without BloodHound.

---

### 👤 User Under Test  
- User: `olivia@administrator.htb`  
- Domain Controller IP: `10.129.227.38`

---

### 🔍 BloodHound Ground Truth  
As confirmed in BloodHound:
<img width="1100" height="459" alt="image" src="https://github.com/user-attachments/assets/37c71aa6-8ec0-4c44-b001-d80ddd2730a0" />

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

