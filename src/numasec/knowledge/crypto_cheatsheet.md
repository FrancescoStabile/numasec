# Cryptography Exploitation Cheatsheet

## Hash Identification & Cracking

### Identify Hash Type
```bash
# By format:
# $1$..........  → MD5 crypt
# $2a$/$2b$/$2y$ → bcrypt
# $5$           → SHA-256 crypt
# $6$           → SHA-512 crypt
# $argon2id$    → Argon2id
# 32 hex chars  → MD5 / NTLM
# 40 hex chars  → SHA-1
# 64 hex chars  → SHA-256
# 128 hex chars → SHA-512

hashid 'HASH_VALUE'
```

### Hashcat Modes (Most Common)
```bash
# Raw hashes
hashcat -m 0    hash.txt wordlist.txt   # MD5
hashcat -m 100  hash.txt wordlist.txt   # SHA-1
hashcat -m 1400 hash.txt wordlist.txt   # SHA-256
hashcat -m 1700 hash.txt wordlist.txt   # SHA-512

# Linux shadow
hashcat -m 500  hash.txt wordlist.txt   # MD5 crypt ($1$)
hashcat -m 1800 hash.txt wordlist.txt   # SHA-512 crypt ($6$)
hashcat -m 3200 hash.txt wordlist.txt   # bcrypt ($2*$)

# Windows
hashcat -m 1000 hash.txt wordlist.txt   # NTLM
hashcat -m 5600 hash.txt wordlist.txt   # NetNTLMv2
hashcat -m 13100 hash.txt wordlist.txt  # Kerberoast (TGS-REP)
hashcat -m 18200 hash.txt wordlist.txt  # AS-REP roast

# Web/Application
hashcat -m 400  hash.txt wordlist.txt   # WordPress (phpass)
hashcat -m 1600 hash.txt wordlist.txt   # Apache $apr1$ MD5
hashcat -m 10000 hash.txt wordlist.txt  # Django PBKDF2-SHA256

# Database
hashcat -m 300  hash.txt wordlist.txt   # MySQL 4.1+
hashcat -m 1731 hash.txt wordlist.txt   # MSSQL 2012+

# Rules for better cracking
hashcat -m 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/rockyou-30000.rule

# Mask attack (brute force patterns)
hashcat -m 0 hash.txt -a 3 ?u?l?l?l?l?d?d?d  # Ullllddd
```

### John the Ripper
```bash
john --wordlist=wordlist.txt hash.txt
john --show hash.txt

# Hash extraction
ssh2john id_rsa > ssh_hash.txt
zip2john protected.zip > zip_hash.txt
keepass2john database.kdbx > kp_hash.txt
pdf2john protected.pdf > pdf_hash.txt
office2john document.docx > office_hash.txt
```

## RSA Attacks

### Small e / Small Plaintext (e=3 cube root)
```python
import gmpy2
# If m^e < n, then c = m^e and m = c^(1/e)
m, exact = gmpy2.iroot(c, e)
if exact:
    print(int(m).to_bytes((int(m).bit_length()+7)//8, 'big'))
```

### Hastad's Broadcast Attack (same m, same small e, different n)
```python
from sympy.ntheory.modular import crt
import gmpy2
remainders = [c1, c2, c3]
moduli = [n1, n2, n3]
result, _ = crt(moduli, remainders)
m, _ = gmpy2.iroot(result, 3)
```

### Wiener's Attack (large e, small d)
```python
# When d < n^0.25 / 3, continued fraction of e/n reveals d
import owiener
d = owiener.attack(e, n)
```

### Fermat Factorization (p ≈ q)
```python
import gmpy2
def fermat_factor(n):
    a = gmpy2.isqrt(n) + 1
    b2 = a * a - n
    while not gmpy2.is_square(b2):
        a += 1
        b2 = a * a - n
    b = gmpy2.isqrt(b2)
    return int(a - b), int(a + b)
```

### Common Factor Attack (shared p between keys)
```python
import math
p = math.gcd(n1, n2)
q1, q2 = n1 // p, n2 // p
```

### Automated Tools
```bash
# factordb — check if n is already factored
python3 -c "from factordb.factordb import FactorDB; f=FactorDB(N); f.connect(); print(f.get_factor_list())"

# RsaCtfTool (tries multiple attacks)
python3 RsaCtfTool.py --publickey pub.pem --private
python3 RsaCtfTool.py --publickey pub.pem --uncipherfile cipher.bin
```

## AES Attacks

### ECB Detection (repeated blocks)
```python
def detect_ecb(ciphertext, block_size=16):
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))  # True = ECB mode
```

### CBC Padding Oracle
```python
# Exploit: decrypt ciphertext by manipulating IV/previous block
# For each byte position (right to left):
#   1. Modify the IV/prev block byte
#   2. Send to server — if padding is valid → derive intermediate value
#   3. XOR with original prev byte → plaintext byte

# Tools: PadBuster, python-paddingoracle
# padbuster URL CIPHERTEXT BLOCK_SIZE
```

### CBC Bit-Flipping
```python
# XOR a byte in block N-1 to change the corresponding byte in block N
# new_prev[i] = original_prev[i] ^ original_plain[i] ^ desired_plain[i]
def cbc_bitflip(prev_block, known_plain, desired_plain, position):
    prev = bytearray(prev_block)
    prev[position] ^= known_plain[position] ^ desired_plain[position]
    return bytes(prev)
```

## TLS/SSL Weaknesses

```bash
# Enumerate TLS configuration
nmap --script ssl-enum-ciphers -p 443 TARGET
sslscan TARGET
testssl.sh TARGET

# Known attacks:
# POODLE (CVE-2014-3566)   — SSLv3 padding oracle
# BEAST (CVE-2011-3389)    — CBC in TLS 1.0
# Heartbleed (CVE-2014-0160) — OpenSSL memory leak
# ROBOT                     — RSA padding oracle (Bleichenbacher)
# FREAK                     — export RSA downgrade
# Logjam                    — export DH downgrade

# Heartbleed
nmap --script ssl-heartbleed -p 443 TARGET
```

## Weak PRNG Exploitation

```python
# Python random (Mersenne Twister) — predictable after 624 outputs
from randcrack import RandCrack
rc = RandCrack()
for _ in range(624):
    rc.submit(get_random_output())  # feed 624 consecutive 32-bit outputs
predicted = rc.predict_getrandbits(32)

# PHP mt_rand — predictable with php_mt_seed
# Java Random — LCG, fully predictable from 2 consecutive outputs
```

## Timing Side-Channels

```python
import time, string

def timing_attack(oracle_func, known="", charset=string.printable):
    """If comparison is byte-by-byte (non-constant-time)"""
    for c in charset:
        attempt = known + c
        times = []
        for _ in range(100):
            start = time.perf_counter_ns()
            oracle_func(attempt)
            times.append(time.perf_counter_ns() - start)
        median = sorted(times)[len(times)//2]
        yield c, median
    # Character with highest median time is likely correct
```

## Common Encoding (Not Encryption)

```bash
# Base64
echo -n "data" | base64
echo "ZGF0YQ==" | base64 -d

# Hex
echo -n "data" | xxd -p
echo "64617461" | xxd -r -p

# ROT13
echo "data" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# XOR with known key
python3 -c "
key = b'KEY'
data = bytes.fromhex('CIPHERTEXT_HEX')
print(bytes(d ^ key[i % len(key)] for i, d in enumerate(data)))
"
```
