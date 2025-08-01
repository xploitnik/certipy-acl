# Handling Output and Data Size

LDAP ACL data can be very large depending on the size of the Active Directory environment you are querying.

To help manage this:

- Use filtering flags (planned or implemented) such as --only-writeowner or --only-genericall to reduce noise.

- Redirect output to a file for easier analysis, for example:
  python3 -m certipy_tool.certipy acl -u user@domain -p pass -target domain.local -dc-ip 10.10.10.10 > acl_output.txt

- JSON output support (planned) will enable automated parsing and integration with other tools.

---

## Important

This tool is currently primitive and designed as a starting point for advanced users.

Contributions to improve filtering, performance, and output formatting are highly welcome.

Feel free to submit issues or pull requests on GitHub.

---

## Suggestions for Use

- Start with smaller scopes or filtered queries to avoid overwhelming output.

- Combine with other enumeration tools for a comprehensive AD security assessment.

- Use output to identify high-value escalation targets such as objects where you have WriteOwner or GenericAll rights.

