# Binary Exploitation Resources

## Essential Tools

| Tool | Purpose | Install |
|------|---------|---------|
| pwntools | Python exploit framework | `pip install pwntools` |
| GEF | GDB enhancement | `bash -c "$(curl -fsSL https://gef.blah.cat/sh)"` |
| pwndbg | GDB enhancement (alt) | `git clone https://github.com/pwndbg/pwndbg` |
| ROPgadget | ROP gadget finder | `pip install ROPgadget` |
| ropper | ROP gadget finder (alt) | `pip install ropper` |
| one_gadget | Find one-shot RCE gadgets in libc | `gem install one_gadget` |
| Ghidra | Decompiler / RE | `ghidra.re` |
| radare2 / rizin | CLI disassembler | `apt install radare2` |
| angr | Symbolic execution | `pip install angr` |
| z3 | SMT solver | `pip install z3-solver` |
| seccomp-tools | Analyze seccomp filters | `gem install seccomp-tools` |
| checksec | Binary security checks | `apt install checksec` |
| ltrace / strace | Library/syscall tracing | `apt install ltrace strace` |

## Libc Database

```bash
# Find libc version from leaked addresses
# https://libc.blukat.me/
# https://libc.rip/

# Local: libc-database
git clone https://github.com/niklasb/libc-database
./get  # download common libcs
./find <leaked_func_name> <last_3_hex_digits>
./dump <libc_id>  # get offsets for system, /bin/sh, etc.
```

## One-Shot Gadgets

```bash
# Find one_gadget in libc (execve("/bin/sh") with constraints)
one_gadget /lib/x86_64-linux-gnu/libc.so.6
# Output: addresses + constraints (e.g., rax == NULL, [rsp+0x30] == NULL)
# Use when you can only overwrite a single pointer (hooks, GOT)
```

## Seccomp Analysis

```bash
# Dump seccomp filter
seccomp-tools dump ./binary

# If only certain syscalls allowed:
# open+read+write → ORW (open-read-write) shellcode
# No execve → can't spawn shell, must read flag directly
```

## Useful Pwntools Patterns

```python
from pwn import *

# Auto-find libc
libc = ELF('./libc.so.6')
libc.address = leaked - libc.symbols['puts']
system = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh\x00'))

# One gadget
one_gadget = libc.address + 0x4f3d5  # from one_gadget output

# ROP chain builder
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])
rop.call('main')
log.info(rop.dump())

# Shellcraft
context.arch = 'amd64'
sc = shellcraft.open('flag.txt') + shellcraft.read('rax', 'rsp', 100) + shellcraft.write(1, 'rsp', 100)
payload = asm(sc)

# Format string
from pwnlib.fmtstr import fmtstr_payload
payload = fmtstr_payload(offset, {target: value}, write_size='short')
```
