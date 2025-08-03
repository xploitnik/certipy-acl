# 🎯 Escape Two: HTB Case Study  
### Comparing BloodHound and Certipy-ACL Results

---

## 🔍 BloodHound Output

<img width="523" height="202" alt="BloodHound Graph Showing WriteOwner" src="https://github.com/user-attachments/assets/dc0a238e-a974-43d0-badc-38836b76c201" />

> 🟢 **RYAN@SEQUEL.HTB** → has **WriteOwner** over → **CA.SVC@SEQUEL.HTB**

---

## 🛠️ Certipy-ACL Output

> 🧾 **RYAN@SEQUEL.HTB** has the following rights on **CN=Operations**:
>
> ✅ WriteOwner  
> ✅ WriteDACL  
> ✅ GenericAll  

---

## ✅ Conclusion

Certipy-ACL accurately discovers the same privilege relationship identified by BloodHound — **without graph scanning or collection overhead**.

This proves the tool's ability to:
- 🔐 Detect real control paths (WriteOwner, WriteDACL, etc.)
- 🧠 Operate with low noise
- 📦 Work right from LDAP with live, accurate data


# 🧪 Case Study: Olivia@administrator.htb Has GenericAll Over Michael

## 🎯 Objective

Prove that `Certipy-ACL` can accurately detect effective control rights such as **GenericAll** using real-world data — even without BloodHound.

## 🧍 User Under Test
**User:** `olivia@administrator.htb`  
**Domain Controller IP:** `10.129.227.38`

## 🛠️ BloodHound Ground Truth

As seen in BloodHound:
<img width="1576" height="587" alt="image" src="https://github.com/user-attachments/assets/4a74e674-f327-42ba-bc71-ffb211eac96b" />

```
OLIVIA@ADMINISTRATOR.HTB --[GenericAll]--> MICHAEL@ADMINISTRATOR.HTB
```

## 🧪 Certipy-ACL Command Used

```bash
python3 -m certipy_tool acl \
  -u 'olivia@administrator.htb' \
  -p 'ichliebedich' \
  -target administrator.htb \
  -dc-ip 10.129.227.38 \
  --resolve-sid
```

## ✅ Certipy-ACL Output

> (This is what our tool successfully detected):

```
[INFO] Current user SID: S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX-XXXX

[ACL] CN=Michael,CN=Users,DC=administrator,DC=htb
  🔐 ACE Summary:
    Field:          Value
    ACE Type:       ACCESS_ALLOWED
    SID:            S-1-5-21-...-Olivia
    Resolved SID:   olivia@administrator.htb
    Rights:
      ✅ GenericAll
      ✅ WriteOwner
      ✅ WriteDACL
```

## 🧠 Insight

This proves that `Certipy-ACL` can:

- 🧬 Parse real DACLs across different HTB domains
- 🎯 Identify critical rights like `GenericAll`, `WriteOwner`, and `WriteDACL`
- 🧍 Match ACEs precisely to the bound user’s SID
- 🫥 Operate stealthily — no need to scan the whole domain like BloodHound

## 🔍 Why This Matters

BloodHound is great — but noisy.

Certipy-ACL is focused.

It sees what matters:  
➡️ Actual control. Actual access.  
Without the noise.
