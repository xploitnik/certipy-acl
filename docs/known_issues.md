# 🧠 Known Limitation: Why Some ACLs Show No ACEs (Even If They Exist)

Welcome to **Certipy ACL**, a tool that allows stealthy, low-privileged enumeration of Active Directory permissions (ACEs) via LDAP.

This tool is designed to help red teamers, pentesters, and defenders **see who really has control** over objects like users, groups, and OUs — without noisy graph generation or full domain scans.

But there's one important limitation we want you to understand up front:

---

## ❗ TL;DR — Why You Might See This Output:

```text
[ACL] CN=SomeObject,CN=Users,DC=domain,DC=local
  [!] No DACL or ACEs present
```

Even when you **know** there are ACEs on the object (like `WriteOwner`, `GenericAll`, etc.)...

---

## 🔍 The Root Cause: Lack of `ReadControl`

In Active Directory, every object's permissions (ACEs) are stored in a field called `nTSecurityDescriptor`, which contains the **DACL**.

To view that DACL, your current user must have the `ReadControl` right.

If your user **does not have `ReadControl`**, the LDAP server will simply respond:
> ❌ "Nope — you can’t see the ACL."

Even if:
- You **have** powerful rights on that object (`WriteOwner`, `WriteDACL`, etc.)
- The DACL is **definitely there**
- You’re able to **write** to the object

If you **can’t read the DACL**, LDAP won't return it — so our tool cannot decode it.

---

## 🧠 Why ChatGPT *Can* Decode ACEs (When You Paste Output)

If you share the **raw LDAP response** or the **security descriptor blob**, ChatGPT can:
- Parse the binary structure
- Extract the SID
- Decode the rights like `WriteOwner`, `GenericAll`, etc.

**Because:**  
> You’ve already passed the data to me directly — without relying on LDAP access rights

In other words:  
**You gave me the sealed letter**. I don't need LDAP to “look through the window.” I can just open and read it.

But if there’s no letter at all (because LDAP hid it)?  
Then even I can’t read what isn’t there.

---

## 💡 How to Work Around It

If you’re running into this limitation:

| Option | Result |
|--------|--------|
| 🔐 Bind with a higher-privileged user (e.g., with `ReadControl`) | ✅ You’ll get full DACLs back |
| 🧰 Dump DACLs using another tool (e.g., Certipy `find`, Impacket `ldapsearch`, or from memory) | ✅ Then run `--dump-acls` to decode offline |
| 🤖 Paste full output here into ChatGPT | ✅ I can parse the DACLs for you if present |
| 👤 Use a low-priv user with no `ReadControl` | ❌ You’ll get no ACEs for some objects, even if you have control |

---

## 🔬 We Tried Fixing This…

We attempted multiple workarounds, including:
- Offline parsing
- Simulating ChatGPT's analysis
- Using backup flags

But the reality is:  
> **If LDAP doesn't send the ACEs back, there's nothing to parse.**

---

## 💬 Recommended ChatGPT Questions

To analyze your ACL output with ChatGPT (when the tool gives limited or no ACEs), paste the full terminal output and ask:

1. **“Can you analyze this Certipy ACL output and tell me which ACEs belong to my current user with SID `S-1-5-...`? Highlight any objects where this SID appears, what rights are granted (like WriteOwner or GenericAll), and ignore anything outside this domain SID or built-in groups.”**

2. **“Can you analyze this Certipy ACL output and list all ACEs found for every object? I want to see the full breakdown — show me the object, SID, rights (like WriteOwner or GenericAll), and ACE type. Don’t filter anything.”**

---

## 🛠 Want to Help?

If you find a stealthy way to extract DACLs without `ReadControl` (e.g., via privilege escalation, alternate LDAP paths, or side channels), we’d love for you to open a pull request or issue. The community will thank you.

---

## 🧩 Summary

- This is **not a bug** in the tool
- It’s **LDAP doing its job**
- Knowing this will help you use Certipy ACL more effectively and realistically

Stay stealthy — and stay curious 🔎

