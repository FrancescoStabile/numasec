# Memory Forensics Cheatsheet (Volatility 2 & 3)

## Memory Acquisition

```bash
# Linux — LiME
sudo insmod lime.ko "path=/tmp/memdump.lime format=lime"

# Windows — WinPMEM
winpmem_mini.exe memdump.raw

# VMware — suspend VM, take .vmem file
# VirtualBox — VBoxManage debugvm <vm> dumpvmcore --filename=dump.elf
```

## Volatility 3 (Current Standard)

### System Info
```bash
vol -f memdump.raw windows.info
vol -f memdump.raw linux.info
```

### Process Analysis
```bash
vol -f memdump.raw windows.pslist          # list processes
vol -f memdump.raw windows.pstree          # tree view
vol -f memdump.raw windows.psscan          # find hidden/unlinked
vol -f memdump.raw windows.cmdline         # command lines
vol -f memdump.raw windows.dlllist         # loaded DLLs
vol -f memdump.raw windows.handles         # open handles
vol -f memdump.raw windows.envars          # environment variables

# Dump process memory
vol -f memdump.raw windows.memmap --pid PID --dump
vol -f memdump.raw windows.dumpfiles --pid PID

# Linux
vol -f memdump.lime linux.pslist
vol -f memdump.lime linux.pstree
```

### Network Analysis
```bash
vol -f memdump.raw windows.netscan         # connections and listeners
vol -f memdump.raw windows.netstat         # active connections
vol -f memdump.lime linux.sockstat         # Linux sockets
```

### Registry (Windows)
```bash
vol -f memdump.raw windows.registry.hivelist
vol -f memdump.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"

# Extract password hashes
vol -f memdump.raw windows.hashdump
vol -f memdump.raw windows.lsadump
vol -f memdump.raw windows.cachedump
```

### File System
```bash
vol -f memdump.raw windows.filescan
vol -f memdump.raw windows.filescan | grep -iE "\.txt|\.doc|password|secret"
vol -f memdump.raw windows.dumpfiles --physaddr OFFSET

# Linux bash history
vol -f memdump.lime linux.bash
```

### Malware Detection
```bash
vol -f memdump.raw windows.malfind         # injected code
vol -f memdump.raw windows.hollowfind      # process hollowing
vol -f memdump.raw windows.modules         # kernel modules
vol -f memdump.raw windows.driverscan      # driver objects
vol -f memdump.raw windows.ssdt            # SSDT hooks

# YARA scanning
vol -f memdump.raw yarascan.YaraScan --yara-file rules.yar
```

### Timeline & Credentials
```bash
vol -f memdump.raw timeliner.Timeliner
# Dumps lsass.exe for mimikatz
vol -f memdump.raw windows.dumpfiles --pid LSASS_PID
# Then: mimikatz "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords"
```

## Volatility 2 (Legacy)

```bash
vol.py -f memdump.raw imageinfo           # identify profile
vol.py -f memdump.raw --profile=PROFILE pslist
vol.py -f memdump.raw --profile=PROFILE pstree
vol.py -f memdump.raw --profile=PROFILE psscan
vol.py -f memdump.raw --profile=PROFILE cmdline
vol.py -f memdump.raw --profile=PROFILE netscan
vol.py -f memdump.raw --profile=PROFILE filescan
vol.py -f memdump.raw --profile=PROFILE hivelist
vol.py -f memdump.raw --profile=PROFILE hashdump
vol.py -f memdump.raw --profile=PROFILE malfind
vol.py -f memdump.raw --profile=PROFILE consoles   # console I/O

# Strings correlation
strings -a -t d memdump.raw > strings.txt
vol.py -f memdump.raw --profile=PROFILE strings -s strings.txt
```

## Investigation Workflow

1. **Identify OS** → `windows.info` or `imageinfo`
2. **Processes** → `pslist`/`pstree`/`psscan` — look for:
   - Suspicious parent-child (Word → cmd.exe)
   - Hidden processes (in psscan but not pslist)
3. **Network** → `netscan` — C2 connections, unusual listeners
4. **Code injection** → `malfind` — PAGE_EXECUTE_READWRITE regions
5. **Files** → `filescan` + `dumpfiles` — suspicious executables
6. **Credentials** → `hashdump`, `lsadump`, dump lsass
7. **Timeline** → `timeliner` to reconstruct events
8. **YARA** → custom rules for known indicators
