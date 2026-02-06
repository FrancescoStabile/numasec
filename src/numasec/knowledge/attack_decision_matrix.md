# Attack Decision Matrix

## Port → Service → Attack Surface

| Port | Service | First Steps |
|------|---------|------------|
| 21 | FTP | Anonymous login, version exploits, credential brute force |
| 22 | SSH | Banner grab (version), credential brute force, key-based auth |
| 23 | Telnet | Often cleartext creds, version exploits |
| 25/587 | SMTP | Open relay, user enumeration (VRFY/EXPN/RCPT), header injection |
| 53 | DNS | Zone transfer (AXFR), subdomain enum, cache poisoning |
| 80/443 | HTTP/S | Full web assessment (see Web Testing below) |
| 88 | Kerberos | AS-REP roasting, Kerberoasting, ticket attacks |
| 110/995 | POP3 | Credential brute force, cleartext sniffing |
| 111 | RPCBind | Enumerate RPC services, NFS shares |
| 135 | MSRPC | Enumerate Windows services, interfaces |
| 139/445 | SMB | Null session, share enum, EternalBlue, relay attacks |
| 389/636 | LDAP | Anonymous bind, user/group enum, injection |
| 443 | HTTPS | TLS vulnerabilities + full web assessment |
| 1433 | MSSQL | Default creds (sa:), xp_cmdshell, linked servers |
| 1521 | Oracle | Default creds, TNS listener attacks |
| 2049 | NFS | no_root_squash, world-readable exports |
| 3306 | MySQL | Default creds, UDF exploitation, file read/write |
| 3389 | RDP | Credential brute force, BlueKeep (CVE-2019-0708) |
| 5432 | PostgreSQL | Default creds (postgres:postgres), COPY TO PROGRAM |
| 5900 | VNC | No-auth/weak auth, screenshot |
| 5985/5986 | WinRM | Credential-based remote execution |
| 6379 | Redis | No-auth command execution, SSH key write |
| 8080/8443 | HTTP alt | Tomcat Manager, Jenkins, admin panels |
| 8888 | HTTP alt | Jupyter Notebook (often no auth) |
| 9200 | Elasticsearch | No-auth, data dump, Groovy RCE |
| 27017 | MongoDB | No-auth, data dump |

## Web Testing Decision Tree

```
1. ENUMERATE
   ├── Technology fingerprint → whatweb, headers
   ├── Directory brute force → ffuf, gobuster
   ├── Virtual hosts → ffuf Host header
   └── Parameters → ffuf parameter fuzzing

2. INPUT TESTING (every parameter, header, cookie)
   ├── ' " → SQL error? → SQLi
   ├── {{7*7}} → 49? → SSTI
   ├── <script> → reflected? → XSS
   ├── ../../../etc/passwd → file content? → LFI
   ├── ; id → command output? → Command Injection
   └── sleep/delay → response slow? → Blind injection

3. AUTHENTICATION
   ├── Default creds
   ├── Brute force (rate-limited?)
   ├── Password reset flaws
   ├── JWT/session manipulation
   └── OAuth/SAML misconfiguration

4. AUTHORIZATION
   ├── IDOR (change user ID in requests)
   ├── Privilege escalation (low-priv → admin)
   ├── Path traversal (/admin, /../admin)
   └── HTTP method override (GET→PUT/DELETE)

5. BUSINESS LOGIC
   ├── Race conditions
   ├── Price manipulation
   ├── Workflow bypass
   └── Upload restrictions bypass
```

## Nmap Scanning Strategy

```bash
# Phase 1: Quick TCP scan (top ports)
nmap -sV -sC -T4 TARGET -oN nmap_initial.txt

# Phase 2: Full TCP port scan
nmap -p- -T4 TARGET -oN nmap_full.txt

# Phase 3: Targeted service scan
nmap -sV -sC -p PORTS TARGET -oN nmap_targeted.txt

# Phase 4: UDP top ports (slow but important)
nmap -sU --top-ports 20 TARGET -oN nmap_udp.txt

# Phase 5: Vulnerability scan
nmap -sV --script vuln -p PORTS TARGET -oN nmap_vuln.txt
```

## Technology → Exploit Mapping

| Technology | Common Vulnerabilities |
|-----------|----------------------|
| WordPress | Plugin vulns, xmlrpc.php brute force, wp-config.php exposure |
| Tomcat | Manager default creds, WAR deploy, AJP Ghostcat |
| Jenkins | /script Groovy console, no auth, credential dumping |
| phpMyAdmin | Default creds, authenticated RCE (older versions) |
| Drupal | Drupalgeddon (CVE-2018-7600), deserialization |
| Joomla | SQLi in components, extension vulnerabilities |
| IIS | Short filename disclosure, WebDAV PUT, .aspx upload |
| Apache Struts | OGNL injection (CVE-2017-5638, CVE-2018-11776) |
| Spring | Spring4Shell (CVE-2022-22965), SpEL injection |
| Node.js/Express | Prototype pollution, SSRF, SSTI (Pug/EJS) |
| Laravel | Debug mode info leak, CVE-2021-3129 (ignition RCE) |
| Flask | Debug mode (Werkzeug console), SSTI (Jinja2) |
| Redis | No-auth → SSH key write, webshell write |
| Elasticsearch | No-auth → data exfil, Groovy script RCE |
| Docker | Exposed API (2375/2376), container escape |
