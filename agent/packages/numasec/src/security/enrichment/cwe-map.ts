/**
 * CWE database and keyword→CWE inference.
 *
 * 87+ CWE entries covering MITRE CWE Top 25 (2024) and all common
 * web vulnerability classes mapped to OWASP Top 10 2021.
 */

export interface CweEntry {
  id: string
  name: string
  description: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  owasp2021: string
}

// Full CWE database — id, name, description, severity, OWASP 2021 category
export const CWE_DATABASE: Record<string, CweEntry> = {
  // A01:2021 — Broken Access Control
  "CWE-22": { id: "CWE-22", name: "Path Traversal", description: "Software uses external input to construct a pathname that should be within a restricted directory, but does not properly neutralize sequences such as '..' that can resolve to a location outside of that directory.", severity: "high", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-23": { id: "CWE-23", name: "Relative Path Traversal", description: "Software uses external input to construct a pathname that should be restricted but does not properly neutralize relative path sequences.", severity: "high", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-35": { id: "CWE-35", name: "Path Traversal: '.../...//'", description: "Software uses external input to construct a pathname but does not properly neutralize '.../...//' sequences.", severity: "high", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-59": { id: "CWE-59", name: "Improper Link Resolution Before File Access", description: "Software attempts to access a file based on the filename, but does not properly prevent the filename from identifying a link or shortcut that resolves to an unintended resource.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-200": { id: "CWE-200", name: "Exposure of Sensitive Information", description: "Software exposes sensitive information to an actor that is not explicitly authorized to have access to that information.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-201": { id: "CWE-201", name: "Insertion of Sensitive Information Into Sent Data", description: "Software sends data to another actor, but a portion of the data includes sensitive information that should not be accessible to that actor.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-219": { id: "CWE-219", name: "Storage of File with Sensitive Data Under Web Root", description: "Software stores sensitive data under the web document root with insufficient access control.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-264": { id: "CWE-264", name: "Permissions, Privileges, and Access Controls", description: "Weaknesses related to the management of permissions, privileges, and other security features used to perform access control.", severity: "high", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-269": { id: "CWE-269", name: "Improper Privilege Management", description: "Software does not properly assign, modify, track, or check privileges for an actor.", severity: "high", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-275": { id: "CWE-275", name: "Permission Issues", description: "Weaknesses related to improper assignment or handling of permissions.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-276": { id: "CWE-276", name: "Incorrect Default Permissions", description: "Software sets insecure default permissions for files, directories, or other resources.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-284": { id: "CWE-284", name: "Improper Access Control", description: "Software does not restrict or incorrectly restricts access to a resource from an unauthorized actor.", severity: "high", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-285": { id: "CWE-285", name: "Improper Authorization", description: "Software does not perform or incorrectly performs an authorization check.", severity: "high", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-352": { id: "CWE-352", name: "Cross-Site Request Forgery", description: "Web application does not sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user.", severity: "high", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-359": { id: "CWE-359", name: "Exposure of Private Personal Information", description: "Software exposes private personal information to an actor that is not explicitly authorized.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-425": { id: "CWE-425", name: "Direct Request (Forced Browsing)", description: "Web application does not adequately enforce appropriate authorization on all restricted URLs.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-441": { id: "CWE-441", name: "Unintended Proxy or Intermediary", description: "Software receives a request and forwards it to an unintended target.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-497": { id: "CWE-497", name: "Exposure of System Data", description: "Software exposes system data or debugging information through output or logging.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-538": { id: "CWE-538", name: "File and Directory Information Exposure", description: "Software places sensitive information into files or directories that are accessible to actors who are allowed to have access to the files, but not to the sensitive information.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-540": { id: "CWE-540", name: "Information Exposure Through Source Code", description: "Source code is accessible to unauthorized actors.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-548": { id: "CWE-548", name: "Directory Listing", description: "Directory listing is inappropriately exposed, yielding potentially sensitive information.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-552": { id: "CWE-552", name: "Files Accessible to External Parties", description: "Software makes files available to external parties despite not being intended for external access.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-566": { id: "CWE-566", name: "Access to User Data Through SQL Query", description: "Software provides users with access to data through SQL queries without properly restricting which data can be accessed.", severity: "high", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-601": { id: "CWE-601", name: "URL Redirection to Untrusted Site", description: "Web application accepts user-controlled input that specifies a link to an external site, and redirects to it.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-639": { id: "CWE-639", name: "Authorization Bypass Through User-Controlled Key", description: "System authorization is based on a key controlled by the user, allowing bypassing by modifying the key value.", severity: "high", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-651": { id: "CWE-651", name: "Information Exposure Through WSDL File", description: "Web service exposes WSDL file containing sensitive information.", severity: "low", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-668": { id: "CWE-668", name: "Exposure of Resource to Wrong Sphere", description: "Software exposes a resource to the wrong control sphere.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-706": { id: "CWE-706", name: "Use of Incorrectly-Resolved Name or Reference", description: "Software uses a name or reference to access a resource, but the name/reference resolves to a resource that is outside of the intended control sphere.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-862": { id: "CWE-862", name: "Missing Authorization", description: "Software does not perform an authorization check when an actor attempts to access a resource.", severity: "high", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-863": { id: "CWE-863", name: "Incorrect Authorization", description: "Software performs an authorization check but incorrectly determines that the actor has permission.", severity: "high", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-913": { id: "CWE-913", name: "Improper Control of Dynamically-Managed Code Resources", description: "Software does not properly restrict read or write access to dynamically managed code resources.", severity: "high", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-922": { id: "CWE-922", name: "Insecure Storage of Sensitive Information", description: "Software stores sensitive information without properly limiting read access.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-942": { id: "CWE-942", name: "Permissive Cross-domain Policy", description: "Web application sets overly permissive cross-domain policy (CORS).", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },
  "CWE-1275": { id: "CWE-1275", name: "Sensitive Cookie with Improper SameSite Attribute", description: "Cookie has an improper SameSite attribute, potentially allowing CSRF.", severity: "medium", owasp2021: "A01:2021 - Broken Access Control" },

  // A02:2021 — Cryptographic Failures
  "CWE-261": { id: "CWE-261", name: "Weak Encoding for Password", description: "Obscuring a password with a trivial encoding does not protect the password.", severity: "high", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-296": { id: "CWE-296", name: "Improper Following of Chain of Trust for Certificate Validation", description: "Software does not follow the chain of trust for certificate validation.", severity: "high", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-310": { id: "CWE-310", name: "Cryptographic Issues", description: "Weaknesses related to the use of cryptography.", severity: "high", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-319": { id: "CWE-319", name: "Cleartext Transmission of Sensitive Information", description: "Software transmits sensitive data in cleartext in a communication channel that can be sniffed.", severity: "high", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-321": { id: "CWE-321", name: "Use of Hard-coded Cryptographic Key", description: "Use of a hard-coded cryptographic key significantly increases the possibility that encrypted data may be recovered.", severity: "high", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-322": { id: "CWE-322", name: "Key Exchange without Entity Authentication", description: "Software performs a key exchange with another entity without verifying the identity.", severity: "high", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-323": { id: "CWE-323", name: "Reusing a Nonce, Key Pair in Encryption", description: "Nonces should only be used once.", severity: "high", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-324": { id: "CWE-324", name: "Use of a Key Past its Expiration Date", description: "Software uses a cryptographic key or password past its expiration date.", severity: "medium", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-325": { id: "CWE-325", name: "Missing Required Cryptographic Step", description: "Software does not implement a required step in a cryptographic algorithm.", severity: "high", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-326": { id: "CWE-326", name: "Inadequate Encryption Strength", description: "Software stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough.", severity: "high", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-327": { id: "CWE-327", name: "Use of a Broken or Risky Cryptographic Algorithm", description: "Use of a broken or risky cryptographic algorithm.", severity: "high", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-328": { id: "CWE-328", name: "Use of Weak Hash", description: "Software uses a weak hash algorithm such as MD5 or SHA1.", severity: "medium", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-329": { id: "CWE-329", name: "Not Using a Random IV with CBC Mode", description: "Not using a random initialization vector with CBC mode cipher.", severity: "medium", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-330": { id: "CWE-330", name: "Use of Insufficiently Random Values", description: "Software uses insufficiently random numbers or values in a security context.", severity: "medium", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-331": { id: "CWE-331", name: "Insufficient Entropy", description: "Software uses an algorithm or scheme that produces insufficient entropy.", severity: "medium", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-335": { id: "CWE-335", name: "Incorrect Usage of Seeds in PRNG", description: "Software uses a PRNG but does not correctly manage seeds.", severity: "medium", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-336": { id: "CWE-336", name: "Same Seed in PRNG", description: "Software uses the same seed each time the PRNG is initialized.", severity: "medium", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-337": { id: "CWE-337", name: "Predictable Seed in PRNG", description: "Software uses a predictable value for the seed of a PRNG.", severity: "medium", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-338": { id: "CWE-338", name: "Use of Cryptographically Weak PRNG", description: "Software uses a PRNG that is not cryptographically strong.", severity: "medium", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-340": { id: "CWE-340", name: "Generation of Predictable Numbers or Identifiers", description: "Software uses a scheme that generates numbers or identifiers that are more predictable than required.", severity: "medium", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-347": { id: "CWE-347", name: "Improper Verification of Cryptographic Signature", description: "Software does not verify or incorrectly verifies the cryptographic signature.", severity: "high", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-523": { id: "CWE-523", name: "Unprotected Transport of Credentials", description: "Login page does not use adequate measures to protect credentials during transmission.", severity: "high", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-757": { id: "CWE-757", name: "Selection of Less-Secure Algorithm During Negotiation", description: "Software selects a less-secure algorithm during negotiation.", severity: "high", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-759": { id: "CWE-759", name: "Use of a One-Way Hash without a Salt", description: "Software uses a one-way hash without a salt.", severity: "medium", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-760": { id: "CWE-760", name: "Use of a One-Way Hash with a Predictable Salt", description: "Software uses a one-way hash with a predictable salt.", severity: "medium", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-780": { id: "CWE-780", name: "Use of RSA Algorithm without OAEP", description: "Software uses the RSA algorithm but does not incorporate OAEP.", severity: "medium", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-818": { id: "CWE-818", name: "Insufficient Transport Layer Protection", description: "Software does not adequately protect data during transport.", severity: "high", owasp2021: "A02:2021 - Cryptographic Failures" },
  "CWE-916": { id: "CWE-916", name: "Password Hash With Insufficient Computational Effort", description: "Software generates a hash for a password but uses a scheme that does not provide sufficient computational effort.", severity: "medium", owasp2021: "A02:2021 - Cryptographic Failures" },

  // A03:2021 — Injection
  "CWE-20": { id: "CWE-20", name: "Improper Input Validation", description: "Software does not validate or incorrectly validates input.", severity: "medium", owasp2021: "A03:2021 - Injection" },
  "CWE-74": { id: "CWE-74", name: "Injection", description: "Software constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but does not neutralize special elements.", severity: "high", owasp2021: "A03:2021 - Injection" },
  "CWE-77": { id: "CWE-77", name: "Command Injection", description: "Software constructs all or part of an OS command using externally-influenced input but does not properly neutralize special elements.", severity: "critical", owasp2021: "A03:2021 - Injection" },
  "CWE-78": { id: "CWE-78", name: "OS Command Injection", description: "Software constructs all or part of an OS command using externally-influenced input, allowing command injection.", severity: "critical", owasp2021: "A03:2021 - Injection" },
  "CWE-79": { id: "CWE-79", name: "Cross-site Scripting (XSS)", description: "Software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output used as a web page.", severity: "medium", owasp2021: "A03:2021 - Injection" },
  "CWE-80": { id: "CWE-80", name: "Basic XSS", description: "Software receives input from an upstream component but does not neutralize or incorrectly neutralizes special characters.", severity: "medium", owasp2021: "A03:2021 - Injection" },
  "CWE-83": { id: "CWE-83", name: "Improper Neutralization of Script in Attributes", description: "Software does not neutralize or incorrectly neutralizes script-related events in HTML attributes.", severity: "medium", owasp2021: "A03:2021 - Injection" },
  "CWE-87": { id: "CWE-87", name: "Failure to Sanitize Alternate XSS Syntax", description: "Software does not sanitize alternate XSS syntax.", severity: "medium", owasp2021: "A03:2021 - Injection" },
  "CWE-88": { id: "CWE-88", name: "Argument Injection", description: "Software does not sufficiently delimit arguments being passed to a component.", severity: "high", owasp2021: "A03:2021 - Injection" },
  "CWE-89": { id: "CWE-89", name: "SQL Injection", description: "Software constructs all or part of an SQL command using externally-influenced input, allowing modification of the intended SQL command.", severity: "critical", owasp2021: "A03:2021 - Injection" },
  "CWE-90": { id: "CWE-90", name: "LDAP Injection", description: "Software constructs all or part of an LDAP query using externally-influenced input.", severity: "high", owasp2021: "A03:2021 - Injection" },
  "CWE-91": { id: "CWE-91", name: "XML Injection", description: "Software does not properly neutralize special elements used in XML.", severity: "high", owasp2021: "A03:2021 - Injection" },
  "CWE-93": { id: "CWE-93", name: "CRLF Injection", description: "Software uses CRLF (carriage return line feed) as a special element but does not neutralize them.", severity: "medium", owasp2021: "A03:2021 - Injection" },
  "CWE-94": { id: "CWE-94", name: "Code Injection", description: "Software constructs all or part of a code segment using externally-influenced input from an upstream component.", severity: "critical", owasp2021: "A03:2021 - Injection" },
  "CWE-95": { id: "CWE-95", name: "Eval Injection", description: "Software evaluates user-controlled input as code using an eval function.", severity: "critical", owasp2021: "A03:2021 - Injection" },
  "CWE-97": { id: "CWE-97", name: "SSI Injection", description: "Software generates a web page that contains Server-Side Include (SSI) directives controlled by the user.", severity: "high", owasp2021: "A03:2021 - Injection" },
  "CWE-98": { id: "CWE-98", name: "Improper Control of Filename for Include", description: "Software allows user input to control which files are included at runtime.", severity: "high", owasp2021: "A03:2021 - Injection" },
  "CWE-113": { id: "CWE-113", name: "HTTP Response Splitting", description: "Software receives data from an upstream component, but does not neutralize CRLF sequences before including the data in outgoing HTTP headers.", severity: "medium", owasp2021: "A03:2021 - Injection" },
  "CWE-116": { id: "CWE-116", name: "Improper Encoding or Escaping of Output", description: "Software prepares a structured message for communication with another component, but encoding or escaping is either missing or done incorrectly.", severity: "high", owasp2021: "A03:2021 - Injection" },
  "CWE-470": { id: "CWE-470", name: "Unsafe Reflection", description: "Software uses external input with reflection to select which classes or code to use, without sufficiently restricting which classes or code can be selected.", severity: "high", owasp2021: "A03:2021 - Injection" },
  "CWE-564": { id: "CWE-564", name: "SQL Injection: Hibernate", description: "Using Hibernate to execute a dynamically-created SQL query built with user-controlled input.", severity: "critical", owasp2021: "A03:2021 - Injection" },
  "CWE-611": { id: "CWE-611", name: "XML External Entity (XXE)", description: "Software processes an XML document that can contain XML entities with URIs that resolve to documents outside the intended sphere of control.", severity: "high", owasp2021: "A03:2021 - Injection" },
  "CWE-643": { id: "CWE-643", name: "XPath Injection", description: "Software uses external input to dynamically construct an XPath expression.", severity: "high", owasp2021: "A03:2021 - Injection" },
  "CWE-917": { id: "CWE-917", name: "Expression Language Injection", description: "Software constructs all or part of an expression language statement using externally-influenced input.", severity: "critical", owasp2021: "A03:2021 - Injection" },
  "CWE-943": { id: "CWE-943", name: "NoSQL Injection", description: "Software constructs NoSQL queries using externally-influenced input that is not properly neutralized.", severity: "high", owasp2021: "A03:2021 - Injection" },
  "CWE-1336": { id: "CWE-1336", name: "Template Injection", description: "Software uses a template engine and constructs templates from user-controlled input.", severity: "critical", owasp2021: "A03:2021 - Injection" },

  // A04:2021 — Insecure Design
  "CWE-209": { id: "CWE-209", name: "Error Message Containing Sensitive Information", description: "Software generates an error message that includes sensitive information about its environment, users, or associated data.", severity: "low", owasp2021: "A04:2021 - Insecure Design" },
  "CWE-256": { id: "CWE-256", name: "Plaintext Storage of a Password", description: "Storing a password in plaintext may result in a system compromise.", severity: "high", owasp2021: "A04:2021 - Insecure Design" },
  "CWE-362": { id: "CWE-362", name: "Race Condition", description: "Software contains a code sequence that can run concurrently with other code, and requires exclusive access to a shared resource, but does not ensure exclusive access.", severity: "medium", owasp2021: "A04:2021 - Insecure Design" },
  "CWE-501": { id: "CWE-501", name: "Trust Boundary Violation", description: "Software mixes trusted and untrusted data in the same data structure or structured message.", severity: "medium", owasp2021: "A04:2021 - Insecure Design" },
  "CWE-522": { id: "CWE-522", name: "Insufficiently Protected Credentials", description: "Software transmits or stores credentials but uses an insecure method.", severity: "high", owasp2021: "A04:2021 - Insecure Design" },
  "CWE-840": { id: "CWE-840", name: "Business Logic Errors", description: "Weaknesses in this category identify some of the underlying problems that commonly allow attackers to manipulate the business logic of an application.", severity: "medium", owasp2021: "A04:2021 - Insecure Design" },
  "CWE-400": { id: "CWE-400", name: "Uncontrolled Resource Consumption", description: "Software does not properly control the allocation and maintenance of a limited resource.", severity: "medium", owasp2021: "A04:2021 - Insecure Design" },
  "CWE-770": { id: "CWE-770", name: "Allocation of Resources Without Limits", description: "Software allocates a reusable resource or group of resources on behalf of an actor without imposing any restrictions on the size or number of resources that can be allocated.", severity: "medium", owasp2021: "A04:2021 - Insecure Design" },

  // A05:2021 — Security Misconfiguration
  "CWE-2": { id: "CWE-2", name: "Environment Configuration", description: "Weaknesses in this category are typically introduced during the configuration of the software's operating environment.", severity: "medium", owasp2021: "A05:2021 - Security Misconfiguration" },
  "CWE-11": { id: "CWE-11", name: "Debug Binary in Production", description: "Debug mode is enabled in production.", severity: "medium", owasp2021: "A05:2021 - Security Misconfiguration" },
  "CWE-16": { id: "CWE-16", name: "Configuration", description: "Weaknesses in this category are typically introduced during the configuration of the software.", severity: "medium", owasp2021: "A05:2021 - Security Misconfiguration" },
  "CWE-260": { id: "CWE-260", name: "Password in Configuration File", description: "Software stores a password in a configuration file that might be accessible to actors who do not know the password.", severity: "high", owasp2021: "A05:2021 - Security Misconfiguration" },
  "CWE-315": { id: "CWE-315", name: "Cleartext Storage of Sensitive Information in a Cookie", description: "Software stores sensitive information in cleartext in a cookie.", severity: "medium", owasp2021: "A05:2021 - Security Misconfiguration" },
  "CWE-444": { id: "CWE-444", name: "HTTP Request Smuggling", description: "Software receives HTTP requests and does not handle inconsistencies in request interpretation.", severity: "high", owasp2021: "A05:2021 - Security Misconfiguration" },
  "CWE-520": { id: "CWE-520", name: ".NET Misconfiguration: Use of Impersonation", description: "Allowing impersonation can escalate attacker privileges.", severity: "medium", owasp2021: "A05:2021 - Security Misconfiguration" },
  "CWE-614": { id: "CWE-614", name: "Sensitive Cookie Without 'Secure' Attribute", description: "Sensitive cookie is set without the 'Secure' attribute.", severity: "medium", owasp2021: "A05:2021 - Security Misconfiguration" },
  "CWE-693": { id: "CWE-693", name: "Protection Mechanism Failure", description: "Software does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks.", severity: "medium", owasp2021: "A05:2021 - Security Misconfiguration" },
  "CWE-756": { id: "CWE-756", name: "Missing Custom Error Page", description: "Software does not return custom error pages to the user, potentially exposing sensitive information.", severity: "low", owasp2021: "A05:2021 - Security Misconfiguration" },
  "CWE-776": { id: "CWE-776", name: "XML Entity Expansion", description: "Software does not properly control the number of recursive entity references.", severity: "medium", owasp2021: "A05:2021 - Security Misconfiguration" },
  "CWE-1004": { id: "CWE-1004", name: "Sensitive Cookie Without 'HttpOnly' Flag", description: "Sensitive cookie is set without the 'HttpOnly' attribute, making it accessible to scripts.", severity: "medium", owasp2021: "A05:2021 - Security Misconfiguration" },
  "CWE-1022": { id: "CWE-1022", name: "Use of Web Link to Untrusted Target with window.opener Access", description: "Web page contains a link to an untrusted external site and does not prevent the linked page from modifying the location of the original page via window.opener.", severity: "low", owasp2021: "A05:2021 - Security Misconfiguration" },

  // A06:2021 — Vulnerable and Outdated Components
  "CWE-937": { id: "CWE-937", name: "Using Components with Known Vulnerabilities", description: "Software contains or uses a third-party component that has known vulnerabilities.", severity: "high", owasp2021: "A06:2021 - Vulnerable and Outdated Components" },
  "CWE-1035": { id: "CWE-1035", name: "Using Components with Known Vulnerabilities", description: "Software uses a component with known vulnerabilities.", severity: "high", owasp2021: "A06:2021 - Vulnerable and Outdated Components" },
  "CWE-1104": { id: "CWE-1104", name: "Use of Unmaintained Third Party Components", description: "Software uses third-party components that are no longer maintained.", severity: "medium", owasp2021: "A06:2021 - Vulnerable and Outdated Components" },

  // A07:2021 — Identification and Authentication Failures
  "CWE-255": { id: "CWE-255", name: "Credentials Management Errors", description: "Weaknesses in this category are related to the management of credentials.", severity: "high", owasp2021: "A07:2021 - Identification and Authentication Failures" },
  "CWE-287": { id: "CWE-287", name: "Improper Authentication", description: "Software does not sufficiently verify that the claimed identity of the actor is correct.", severity: "high", owasp2021: "A07:2021 - Identification and Authentication Failures" },
  "CWE-288": { id: "CWE-288", name: "Authentication Bypass Using an Alternate Path", description: "Software requires authentication, but allows an alternate path or channel that does not require authentication.", severity: "high", owasp2021: "A07:2021 - Identification and Authentication Failures" },
  "CWE-290": { id: "CWE-290", name: "Authentication Bypass by Spoofing", description: "Software authenticates or identifies an entity based on evidence that can be spoofed.", severity: "high", owasp2021: "A07:2021 - Identification and Authentication Failures" },
  "CWE-294": { id: "CWE-294", name: "Authentication Bypass by Capture-replay", description: "Software uses a mechanism that authenticates by simply replaying previous communications.", severity: "high", owasp2021: "A07:2021 - Identification and Authentication Failures" },
  "CWE-295": { id: "CWE-295", name: "Improper Certificate Validation", description: "Software does not validate, or incorrectly validates, a certificate.", severity: "high", owasp2021: "A07:2021 - Identification and Authentication Failures" },
  "CWE-306": { id: "CWE-306", name: "Missing Authentication for Critical Function", description: "Software does not perform any authentication for functionality that requires a provable user identity.", severity: "critical", owasp2021: "A07:2021 - Identification and Authentication Failures" },
  "CWE-307": { id: "CWE-307", name: "Improper Restriction of Excessive Authentication Attempts", description: "Software does not implement sufficient anti-automation or rate limiting to prevent brute-force credential attacks.", severity: "high", owasp2021: "A07:2021 - Identification and Authentication Failures" },
  "CWE-345": { id: "CWE-345", name: "Insufficient Verification of Data Authenticity", description: "Software does not sufficiently verify the origin or authenticity of data.", severity: "high", owasp2021: "A08:2021 - Software and Data Integrity Failures" },
  "CWE-384": { id: "CWE-384", name: "Session Fixation", description: "Software accepts a session identifier that was generated externally.", severity: "high", owasp2021: "A07:2021 - Identification and Authentication Failures" },
  "CWE-521": { id: "CWE-521", name: "Weak Password Requirements", description: "Software does not require that users choose sufficiently strong passwords.", severity: "medium", owasp2021: "A07:2021 - Identification and Authentication Failures" },
  "CWE-613": { id: "CWE-613", name: "Insufficient Session Expiration", description: "Software does not sufficiently enforce session timeout.", severity: "medium", owasp2021: "A07:2021 - Identification and Authentication Failures" },
  "CWE-640": { id: "CWE-640", name: "Weak Password Recovery Mechanism", description: "Software contains a mechanism for users to recover or change their passwords but the mechanism is weak.", severity: "medium", owasp2021: "A07:2021 - Identification and Authentication Failures" },
  "CWE-798": { id: "CWE-798", name: "Use of Hard-coded Credentials", description: "Software contains hard-coded credentials for an inbound or outbound connection.", severity: "critical", owasp2021: "A07:2021 - Identification and Authentication Failures" },

  // A08:2021 — Software and Data Integrity Failures
  "CWE-353": { id: "CWE-353", name: "Missing Support for Integrity Check", description: "Software uses a transmission protocol that does not include a mechanism for verifying the integrity of the data during transmission.", severity: "medium", owasp2021: "A08:2021 - Software and Data Integrity Failures" },
  "CWE-426": { id: "CWE-426", name: "Untrusted Search Path", description: "Software uses a search path that contains an untrusted directory.", severity: "high", owasp2021: "A08:2021 - Software and Data Integrity Failures" },
  "CWE-434": { id: "CWE-434", name: "Unrestricted Upload of File with Dangerous Type", description: "Software allows the attacker to upload or transfer files of dangerous types.", severity: "high", owasp2021: "A08:2021 - Software and Data Integrity Failures" },
  "CWE-502": { id: "CWE-502", name: "Deserialization of Untrusted Data", description: "Software deserializes untrusted data without sufficiently verifying that the resulting data will be valid.", severity: "critical", owasp2021: "A08:2021 - Software and Data Integrity Failures" },
  "CWE-565": { id: "CWE-565", name: "Reliance on Cookies without Validation", description: "Software relies on the existence or values of cookies without properly validating them.", severity: "medium", owasp2021: "A08:2021 - Software and Data Integrity Failures" },
  "CWE-829": { id: "CWE-829", name: "Inclusion of Functionality from Untrusted Control Sphere", description: "Software imports, requires, or includes executable functionality from a source that is outside of the intended control sphere.", severity: "medium", owasp2021: "A08:2021 - Software and Data Integrity Failures" },
  "CWE-915": { id: "CWE-915", name: "Mass Assignment", description: "Software provides an API that allows callers to specify fields to modify, but does not sufficiently restrict which fields can be modified.", severity: "high", owasp2021: "A08:2021 - Software and Data Integrity Failures" },

  // A09:2021 — Security Logging and Monitoring Failures
  "CWE-117": { id: "CWE-117", name: "Improper Output Neutralization for Logs", description: "Software does not neutralize or incorrectly neutralizes output that is written to logs.", severity: "medium", owasp2021: "A09:2021 - Security Logging and Monitoring Failures" },
  "CWE-223": { id: "CWE-223", name: "Omission of Security-relevant Information", description: "Software does not record or display information that would be important for identifying the source or nature of an attack.", severity: "medium", owasp2021: "A09:2021 - Security Logging and Monitoring Failures" },
  "CWE-532": { id: "CWE-532", name: "Sensitive Information into Log File", description: "Information written to log files can be of a sensitive nature.", severity: "medium", owasp2021: "A09:2021 - Security Logging and Monitoring Failures" },
  "CWE-778": { id: "CWE-778", name: "Insufficient Logging", description: "Software does not log critical security events or does not log enough information to enable a security investigation.", severity: "medium", owasp2021: "A09:2021 - Security Logging and Monitoring Failures" },

  // A10:2021 — Server-Side Request Forgery (SSRF)
  "CWE-918": { id: "CWE-918", name: "Server-Side Request Forgery (SSRF)", description: "Software receives a URL from an upstream component and retrieves the contents without verifying that the request is being sent to an appropriate destination.", severity: "high", owasp2021: "A10:2021 - Server-Side Request Forgery (SSRF)" },

  // Additional
  "CWE-1321": { id: "CWE-1321", name: "Prototype Pollution", description: "Software allows modification of object prototypes, potentially leading to code execution or denial of service.", severity: "high", owasp2021: "A03:2021 - Injection" },
  "CWE-1385": { id: "CWE-1385", name: "WebSocket Hijacking", description: "Missing origin validation in WebSocket handshake allows cross-site WebSocket hijacking.", severity: "high", owasp2021: "A01:2021 - Broken Access Control" },
}

/**
 * Keyword → CWE mapping for inference from finding titles/descriptions.
 * Keys are lowercased. First match wins.
 */
export const VULN_CWE_MAP: Record<string, { id: string; name: string }> = {
  // Injection
  "sqli": { id: "CWE-89", name: "SQL Injection" },
  "sql injection": { id: "CWE-89", name: "SQL Injection" },
  "xss": { id: "CWE-79", name: "Cross-site Scripting" },
  "cross-site scripting": { id: "CWE-79", name: "Cross-site Scripting" },
  "csrf": { id: "CWE-352", name: "Cross-Site Request Forgery" },
  "cross-site request forgery": { id: "CWE-352", name: "Cross-Site Request Forgery" },
  "ssrf": { id: "CWE-918", name: "Server-Side Request Forgery" },
  "server-side request forgery": { id: "CWE-918", name: "Server-Side Request Forgery" },
  "lfi": { id: "CWE-98", name: "Improper Control of Filename for Include" },
  "local file inclusion": { id: "CWE-98", name: "Improper Control of Filename for Include" },
  "rfi": { id: "CWE-98", name: "Improper Control of Filename for Include" },
  "remote file inclusion": { id: "CWE-98", name: "Improper Control of Filename for Include" },
  "ssti": { id: "CWE-1336", name: "Template Injection" },
  "server-side template injection": { id: "CWE-1336", name: "Template Injection" },
  "template injection": { id: "CWE-1336", name: "Template Injection" },
  "idor": { id: "CWE-639", name: "Authorization Bypass Through User-Controlled Key" },
  "insecure direct object reference": { id: "CWE-639", name: "Authorization Bypass Through User-Controlled Key" },
  "command injection": { id: "CWE-78", name: "OS Command Injection" },
  "os command injection": { id: "CWE-78", name: "OS Command Injection" },
  "xxe": { id: "CWE-611", name: "XML External Entity" },
  "xml external entity": { id: "CWE-611", name: "XML External Entity" },
  "deserialization": { id: "CWE-502", name: "Deserialization of Untrusted Data" },
  "insecure deserialization": { id: "CWE-502", name: "Deserialization of Untrusted Data" },
  "default credentials": { id: "CWE-798", name: "Use of Hard-coded Credentials" },
  "hard-coded credentials": { id: "CWE-798", name: "Use of Hard-coded Credentials" },
  "hardcoded credentials": { id: "CWE-798", name: "Use of Hard-coded Credentials" },
  "information disclosure": { id: "CWE-200", name: "Information Exposure" },
  "information exposure": { id: "CWE-200", name: "Information Exposure" },
  "sensitive data exposure": { id: "CWE-200", name: "Information Exposure" },
  "misconfiguration": { id: "CWE-16", name: "Configuration" },
  "security misconfiguration": { id: "CWE-16", name: "Configuration" },
  "cors": { id: "CWE-942", name: "Permissive Cross-domain Policy" },
  "cors misconfiguration": { id: "CWE-942", name: "Permissive Cross-domain Policy" },
  "open redirect": { id: "CWE-601", name: "URL Redirection to Untrusted Site" },
  "url redirection": { id: "CWE-601", name: "URL Redirection to Untrusted Site" },
  "path traversal": { id: "CWE-22", name: "Path Traversal" },
  "directory traversal": { id: "CWE-22", name: "Path Traversal" },
  "authentication bypass": { id: "CWE-287", name: "Improper Authentication" },
  "improper authentication": { id: "CWE-287", name: "Improper Authentication" },
  "broken authentication": { id: "CWE-287", name: "Improper Authentication" },
  "broken access control": { id: "CWE-284", name: "Improper Access Control" },
  "improper access control": { id: "CWE-284", name: "Improper Access Control" },
  "missing authorization": { id: "CWE-862", name: "Missing Authorization" },
  "incorrect authorization": { id: "CWE-863", name: "Incorrect Authorization" },
  "forced browsing": { id: "CWE-425", name: "Direct Request (Forced Browsing)" },
  "directory listing": { id: "CWE-548", name: "Directory Listing" },
  "privilege escalation": { id: "CWE-269", name: "Improper Privilege Management" },
  "session fixation": { id: "CWE-384", name: "Session Fixation" },
  "weak cipher": { id: "CWE-326", name: "Inadequate Encryption Strength" },
  "weak encryption": { id: "CWE-326", name: "Inadequate Encryption Strength" },
  "weak cryptography": { id: "CWE-327", name: "Use of a Broken or Risky Cryptographic Algorithm" },
  "broken crypto": { id: "CWE-327", name: "Use of a Broken or Risky Cryptographic Algorithm" },
  "cleartext transmission": { id: "CWE-319", name: "Cleartext Transmission of Sensitive Information" },
  "missing https": { id: "CWE-319", name: "Cleartext Transmission of Sensitive Information" },
  "weak hash": { id: "CWE-328", name: "Use of Weak Hash" },
  "md5": { id: "CWE-328", name: "Use of Weak Hash" },
  "sha1": { id: "CWE-328", name: "Use of Weak Hash" },
  "weak password hash": { id: "CWE-916", name: "Password Hash With Insufficient Computational Effort" },
  "missing salt": { id: "CWE-759", name: "Use of a One-Way Hash without a Salt" },
  "insufficient entropy": { id: "CWE-331", name: "Insufficient Entropy" },
  "weak random": { id: "CWE-330", name: "Use of Insufficiently Random Values" },
  "predictable token": { id: "CWE-330", name: "Use of Insufficiently Random Values" },
  "certificate validation": { id: "CWE-295", name: "Improper Certificate Validation" },
  "ssl": { id: "CWE-295", name: "Improper Certificate Validation" },
  "tls": { id: "CWE-295", name: "Improper Certificate Validation" },
  "business logic": { id: "CWE-840", name: "Business Logic Errors" },
  "race condition": { id: "CWE-362", name: "Race Condition" },
  "trust boundary": { id: "CWE-501", name: "Trust Boundary Violation" },
  "error message": { id: "CWE-209", name: "Error Message Containing Sensitive Information" },
  "verbose error": { id: "CWE-209", name: "Error Message Containing Sensitive Information" },
  "stack trace": { id: "CWE-209", name: "Error Message Containing Sensitive Information" },
  "debug mode": { id: "CWE-11", name: "Debug Binary in Production" },
  "missing security header": { id: "CWE-16", name: "Configuration" },
  "missing httponly": { id: "CWE-1004", name: "Sensitive Cookie Without 'HttpOnly' Flag" },
  "missing secure flag": { id: "CWE-614", name: "Sensitive Cookie Without 'Secure' Attribute" },
  "cookie without secure": { id: "CWE-614", name: "Sensitive Cookie Without 'Secure' Attribute" },
  "cookie without httponly": { id: "CWE-1004", name: "Sensitive Cookie Without 'HttpOnly' Flag" },
  "samesite": { id: "CWE-1275", name: "Sensitive Cookie with Improper SameSite Attribute" },
  "xml entity expansion": { id: "CWE-776", name: "XML Entity Expansion" },
  "outdated component": { id: "CWE-1104", name: "Use of Unmaintained Third Party Components" },
  "known vulnerability": { id: "CWE-1035", name: "Using Components with Known Vulnerabilities" },
  "outdated software": { id: "CWE-1104", name: "Use of Unmaintained Third Party Components" },
  "vulnerable component": { id: "CWE-937", name: "Using Components with Known Vulnerabilities" },
  "outdated library": { id: "CWE-1104", name: "Use of Unmaintained Third Party Components" },
  "brute force": { id: "CWE-307", name: "Improper Restriction of Excessive Authentication Attempts" },
  "weak password": { id: "CWE-521", name: "Weak Password Requirements" },
  "session expiration": { id: "CWE-613", name: "Insufficient Session Expiration" },
  "password recovery": { id: "CWE-640", name: "Weak Password Recovery Mechanism" },
  "missing authentication": { id: "CWE-306", name: "Missing Authentication for Critical Function" },
  "file upload": { id: "CWE-434", name: "Unrestricted Upload of File with Dangerous Type" },
  "unrestricted upload": { id: "CWE-434", name: "Unrestricted Upload of File with Dangerous Type" },
  "mass assignment": { id: "CWE-915", name: "Mass Assignment" },
  "improperly controlled modification": { id: "CWE-915", name: "Mass Assignment" },
  "log injection": { id: "CWE-117", name: "Improper Output Neutralization for Logs" },
  "insufficient logging": { id: "CWE-778", name: "Insufficient Logging" },
  "sensitive data in log": { id: "CWE-532", name: "Sensitive Information into Log File" },
  "ldap injection": { id: "CWE-90", name: "LDAP Injection" },
  "xpath injection": { id: "CWE-643", name: "XPath Injection" },
  "code injection": { id: "CWE-94", name: "Code Injection" },
  "eval injection": { id: "CWE-95", name: "Eval Injection" },
  "crlf injection": { id: "CWE-93", name: "CRLF Injection" },
  "http response splitting": { id: "CWE-113", name: "HTTP Response Splitting" },
  "header injection": { id: "CWE-113", name: "HTTP Response Splitting" },
  "expression language injection": { id: "CWE-917", name: "Expression Language Injection" },
  "nosql injection": { id: "CWE-943", name: "NoSQL Injection" },
  "nosql": { id: "CWE-943", name: "NoSQL Injection" },
  "http smuggling": { id: "CWE-444", name: "HTTP Request Smuggling" },
  "request smuggling": { id: "CWE-444", name: "HTTP Request Smuggling" },
  "prototype pollution": { id: "CWE-1321", name: "Prototype Pollution" },
  "websocket hijacking": { id: "CWE-1385", name: "WebSocket Hijacking" },
}

/**
 * Infer CWE from a finding's title and description.
 * Searches keywords in the combined text, returns first match.
 */
export function getCweInfo(title: string, description = ""): { id: string; name: string } | undefined {
  const text = `${title} ${description}`.toLowerCase()
  for (const [keyword, info] of Object.entries(VULN_CWE_MAP)) {
    if (text.includes(keyword)) return info
  }
  return undefined
}

/**
 * Get full CWE details from the database.
 */
export function getCweDetails(cweId: string): CweEntry | undefined {
  return CWE_DATABASE[cweId]
}
