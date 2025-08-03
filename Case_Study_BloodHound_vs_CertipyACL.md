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
