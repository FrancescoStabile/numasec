# OSINT & Reconnaissance Cheatsheet

## Subdomain Enumeration

```bash
# Passive — certificate transparency logs
curl -s "https://crt.sh/?q=%25.TARGET.com&output=json" | jq -r '.[].name_value' | sort -u

# Passive — subfinder (multi-source)
subfinder -d TARGET.com -all -o subdomains.txt

# Passive — amass
amass enum -passive -d TARGET.com -o amass_subs.txt

# Active — brute force
gobuster dns -d TARGET.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50
ffuf -u http://FUZZ.TARGET.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,301,302,403

# DNS zone transfer attempt
dig axfr @ns1.TARGET.com TARGET.com

# Resolve all discovered subdomains
cat subdomains.txt | httpx -silent -status-code -title -tech-detect -o alive.txt
```

## DNS Reconnaissance

```bash
# All record types
dig TARGET.com ANY +noall +answer
dig TARGET.com A AAAA CNAME MX NS TXT SOA +noall +answer

# Reverse DNS
dig -x IP_ADDRESS

# SPF/DMARC (email security)
dig TARGET.com TXT | grep "v=spf1"
dig _dmarc.TARGET.com TXT

# ASN lookup
whois -h whois.cymru.com " -v IP_ADDRESS"
curl -s "https://api.bgpview.io/ip/IP_ADDRESS" | jq
```

## Web Technology Fingerprinting

```bash
# Wappalyzer / whatweb
whatweb TARGET.com

# HTTP headers
curl -sI TARGET.com | grep -iE "server|x-powered|x-aspnet|x-generator"

# httpx (bulk)
echo TARGET.com | httpx -tech-detect -status-code -title -web-server -cdn
```

## Search Engine Dorking

```
# Google Dorks
site:TARGET.com filetype:pdf
site:TARGET.com inurl:admin
site:TARGET.com intitle:"index of"
site:TARGET.com ext:sql | ext:bak | ext:old | ext:conf
site:TARGET.com intext:password
"TARGET.com" filetype:env | filetype:cfg | filetype:ini

# Find subdomains via Google
site:*.TARGET.com -www

# GitHub Dorks
"TARGET.com" password
"TARGET.com" secret
org:TARGET_ORG filename:.env
org:TARGET_ORG filename:docker-compose.yml
org:TARGET_ORG filename:id_rsa
```

## Shodan / Censys / ZoomEye

```bash
# Shodan CLI
shodan search hostname:TARGET.com
shodan host IP_ADDRESS
shodan search "ssl.cert.subject.cn:TARGET.com" --fields ip_str,port,org

# Shodan queries for vulns
shodan search vuln:CVE-2021-44228  # Log4Shell
shodan search "http.component:wordpress"
shodan search 'product:Apache httpd version:2.4.49'

# Censys
censys search "TARGET.com" --index-type hosts
```

## Email & Credential Intel

```bash
# Email harvesting
theHarvester -d TARGET.com -b all

# Breach data (ethical use only)
# → haveibeenpwned.com API (per email)
# → dehashed.com (search by domain)

# Verify emails exist
# → hunter.io (find corporate email patterns)
```

## Metadata Extraction

```bash
# Documents and images (author, software, GPS, timestamps)
exiftool document.pdf
exiftool image.jpg
exiftool -gps* image.jpg

# Bulk metadata from website
wget -r -l1 -A pdf,doc,docx,xls,xlsx TARGET.com/documents/
exiftool -r downloaded_dir/ | grep -iE "author|creator|producer|company"
```

## Infrastructure Mapping

```bash
# CDN/WAF detection
wafw00f TARGET.com
dig TARGET.com CNAME  # check for cloudfront, akamai, cloudflare

# Find origin IP behind CDN
# → Check historical DNS (SecurityTrails)
# → Censys search by SSL cert serial number
censys search "services.tls.certificates.leaf.fingerprint_sha256:CERT_HASH"

# Virtual host discovery (same IP, different domain)
curl -s "https://api.hackertarget.com/reverseiplookup/?q=IP_ADDRESS"
```

## Wayback Machine & Web Archives

```bash
# Find historical pages
curl -s "https://web.archive.org/cdx/search/cdx?url=TARGET.com/*&output=text&fl=original&collapse=urlkey" | sort -u

# waybackurls + GAU
waybackurls TARGET.com | grep -iE "\.env|\.git|config|admin|backup|api" | sort -u
gau TARGET.com | sort -u

# Check for interesting files in history
waybackurls TARGET.com | grep -iE "\.(sql|bak|old|zip|tar|conf|cfg|env|log)$"
```

## Social Media & Username OSINT

```bash
# Username across platforms
sherlock USERNAME

# GitHub user analysis
curl -s "https://api.github.com/users/USERNAME/repos" | jq -r '.[].name'
# Check: commits, email in git log, secrets in repos
# → gitleaks for secrets scanning
```
