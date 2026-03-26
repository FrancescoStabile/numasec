"""Ground truth vulnerability definitions for benchmark targets."""

from __future__ import annotations

DVWA_GROUND_TRUTH = {
    "target": "http://localhost:8080",
    "vulns": [
        {"type": "sqli", "location": "/vulnerabilities/sqli/", "severity": "high"},
        {"type": "xss_reflected", "location": "/vulnerabilities/xss_r/", "severity": "medium"},
        {"type": "xss_stored", "location": "/vulnerabilities/xss_s/", "severity": "high"},
        {"type": "command_injection", "location": "/vulnerabilities/exec/", "severity": "critical"},
        {"type": "file_inclusion", "location": "/vulnerabilities/fi/", "severity": "high"},
        {"type": "csrf", "location": "/vulnerabilities/csrf/", "severity": "medium"},
        {"type": "file_upload", "location": "/vulnerabilities/upload/", "severity": "high"},
    ],
}

JUICE_SHOP_GROUND_TRUTH = {
    "target": "http://localhost:3000",
    "vulns": [
        # --- Injection (OWASP A03) ---
        {"type": "sqli", "location": "/rest/products/search", "severity": "high",
         "description": "SQLi in product search via q= parameter"},
        {"type": "sqli_auth_bypass", "location": "/rest/user/login", "severity": "critical",
         "description": "SQL injection login bypass: ' OR 1=1-- in email field"},
        {"type": "nosql_injection", "location": "/rest/products/reviews", "severity": "high",
         "description": "NoSQL injection in product review endpoint"},
        {"type": "xxe", "location": "/file-upload", "severity": "high",
         "description": "XXE via XML file upload in complaint form"},
        # --- XSS (OWASP A03) ---
        {"type": "xss_dom", "location": "/#/search", "severity": "medium",
         "description": "DOM XSS in Angular search via URL fragment"},
        {"type": "xss_reflected", "location": "/#/track-result", "severity": "medium",
         "description": "Reflected XSS in order tracking result page"},
        {"type": "xss_stored", "location": "/api/Feedbacks", "severity": "high",
         "description": "Stored XSS via feedback comment field"},
        # --- Broken Access Control (OWASP A01) ---
        {"type": "idor", "location": "/rest/basket/", "severity": "high",
         "description": "IDOR on basket endpoint — access other users' baskets"},
        {"type": "idor", "location": "/api/Users/", "severity": "high",
         "description": "IDOR on Users API — enumerate user accounts"},
        {"type": "idor", "location": "/api/Cards/", "severity": "high",
         "description": "IDOR on Cards API — access other users' credit cards"},
        {"type": "forged_feedback", "location": "/api/Feedbacks", "severity": "medium",
         "description": "POST feedback with arbitrary userId (broken access control)"},
        {"type": "admin_access", "location": "/#/administration", "severity": "high",
         "description": "Admin panel accessible without proper authorization"},
        # --- Broken Authentication (OWASP A07) ---
        {"type": "auth_bypass", "location": "/rest/user/login", "severity": "critical",
         "description": "Authentication bypass via SQLi or default credentials"},
        {"type": "broken_auth", "location": "/rest/user/change-password", "severity": "high",
         "description": "Password change without current password verification"},
        {"type": "jwt_weak", "location": "/rest/user/login", "severity": "critical",
         "description": "JWT with weak HS256 secret and alg:none accepted"},
        {"type": "default_credentials", "location": "/rest/user/login", "severity": "high",
         "description": "Default admin credentials (admin@juice-sh.op / admin123)"},
        # --- Sensitive Data Exposure (OWASP A02) ---
        {"type": "sensitive_data_exposure", "location": "/ftp/", "severity": "high",
         "description": "FTP directory with confidential files exposed"},
        {"type": "path_traversal", "location": "/ftp/", "severity": "high",
         "description": "Null byte path traversal bypasses file extension check"},
        {"type": "exposed_api", "location": "/api/Users", "severity": "high",
         "description": "User listing API leaks emails, roles, and password hashes"},
        {"type": "exposed_api", "location": "/api/Cards", "severity": "high",
         "description": "Credit card API leaks full card numbers"},
        # --- Security Misconfiguration (OWASP A05) ---
        {"type": "security_misconfiguration", "location": "/", "severity": "medium",
         "description": "Verbose error messages with stack traces and SQL details"},
        {"type": "missing_headers", "location": "/", "severity": "low",
         "description": "Missing security headers (CSP, X-Frame-Options, etc.)"},
        {"type": "open_redirect", "location": "/redirect", "severity": "medium",
         "description": "Open redirect via to= parameter with allowlist bypass"},
        # --- CSRF (OWASP A01) ---
        {"type": "csrf", "location": "/profile", "severity": "medium",
         "description": "CSRF on profile/username change — no anti-CSRF token"},
        # --- Broken Anti-Automation ---
        {"type": "captcha_bypass", "location": "/api/Feedbacks", "severity": "low",
         "description": "CAPTCHA can be bypassed by removing captchaId from request"},
        # --- SSRF (OWASP A10) ---
        {"type": "ssrf", "location": "/profile/image/url", "severity": "medium",
         "description": "SSRF via profile image URL parameter"},
    ],
}

WEBGOAT_GROUND_TRUTH = {
    "target": "http://localhost:8081/WebGoat",
    "vulns": [
        # --- Injection (A03) ---
        {"type": "sqli", "location": "/SqlInjection/attack5a", "severity": "critical",
         "description": "String SQL injection in login form"},
        {"type": "sqli", "location": "/SqlInjection/attack5b", "severity": "critical",
         "description": "Numeric SQL injection in account number field"},
        {"type": "sqli_union", "location": "/SqlInjectionAdvanced/challenge", "severity": "critical",
         "description": "UNION-based SQL injection in advanced challenge"},
        {"type": "sqli_blind", "location": "/SqlInjectionMitigations/servers", "severity": "high",
         "description": "Blind SQL injection with ORDER BY clause"},
        {"type": "xxe", "location": "/xxe/simple", "severity": "high",
         "description": "XXE via XML comment submission"},
        {"type": "xxe_blind", "location": "/xxe/blind", "severity": "high",
         "description": "Blind XXE with out-of-band data exfiltration"},
        {"type": "xss_reflected", "location": "/CrossSiteScripting/attack5a", "severity": "medium",
         "description": "Reflected XSS in search field"},
        {"type": "xss_dom", "location": "/CrossSiteScripting/phone-home-xss", "severity": "medium",
         "description": "DOM-based XSS via phone home callback"},
        # --- Broken Access Control (A01) ---
        {"type": "idor", "location": "/IDOR/profile", "severity": "high",
         "description": "IDOR on user profile endpoint via userId parameter"},
        {"type": "path_traversal", "location": "/PathTraversal/random", "severity": "high",
         "description": "Path traversal in file upload/download endpoint"},
        {"type": "missing_access_control", "location": "/access-control/users", "severity": "high",
         "description": "Missing function-level access control on admin endpoint"},
        # --- Broken Authentication (A07) ---
        {"type": "auth_bypass", "location": "/auth-bypass/verify-account", "severity": "high",
         "description": "Authentication bypass via security question manipulation"},
        {"type": "jwt_weak", "location": "/JWT/decode", "severity": "high",
         "description": "JWT with weak HS256 secret and alg confusion"},
        {"type": "insecure_login", "location": "/InsecureLogin/task", "severity": "high",
         "description": "Credentials transmitted in plaintext (base64 in POST body)"},
        {"type": "password_reset", "location": "/PasswordReset/reset/login", "severity": "medium",
         "description": "Insecure password reset via predictable token"},
        # --- Cryptographic Failures (A02) ---
        {"type": "insecure_crypto", "location": "/crypto/encoding/basic", "severity": "medium",
         "description": "Base64 encoding used instead of encryption for secrets"},
        # --- Security Misconfiguration (A05) ---
        {"type": "security_misconfiguration", "location": "/", "severity": "medium",
         "description": "Spring Boot actuator endpoints exposed, verbose error pages"},
        # --- SSRF (A10) ---
        {"type": "ssrf", "location": "/SSRF/task1", "severity": "high",
         "description": "SSRF via URL parameter in image proxy"},
        {"type": "ssrf", "location": "/SSRF/task2", "severity": "high",
         "description": "SSRF to internal service via redirect bypass"},
        # --- CSRF (A01) ---
        {"type": "csrf", "location": "/csrf/basic-get-flag", "severity": "medium",
         "description": "CSRF on state-changing GET request"},
    ],
}


# Aliases for scoring: maps alternative names to canonical ground-truth types
_TYPE_ALIASES: dict[str, list[str]] = {
    "sqli": ["sql_injection", "sql-injection", "injection"],
    "sqli_auth_bypass": ["auth_bypass", "authentication_bypass", "login_bypass", "sqli"],
    "xss_dom": ["dom_xss", "xss", "cross_site_scripting"],
    "xss_reflected": ["reflected_xss", "xss", "cross_site_scripting"],
    "xss_stored": ["stored_xss", "xss", "cross_site_scripting"],
    "nosql_injection": ["nosql", "nosqli", "mongodb_injection"],
    "idor": ["insecure_direct_object_reference", "bola", "broken_object_level_authorization"],
    "auth_bypass": ["authentication_bypass", "sqli_auth_bypass", "broken_authentication"],
    "broken_auth": ["broken_authentication", "password_change", "auth"],
    "jwt_weak": ["jwt", "json_web_token", "weak_jwt", "jwt_none"],
    "csrf": ["cross_site_request_forgery"],
    "xxe": ["xml_external_entity", "xml_injection"],
    "ssrf": ["server_side_request_forgery"],
    "open_redirect": ["redirect", "url_redirect"],
    "path_traversal": ["lfi", "local_file_inclusion", "directory_traversal", "null_byte"],
    "security_misconfiguration": ["misconfiguration", "verbose_error", "error_handling"],
    "sensitive_data_exposure": ["data_exposure", "information_disclosure", "ftp"],
    "exposed_api": ["api_exposure", "information_disclosure", "data_exposure"],
    "missing_headers": ["security_headers", "header_misconfiguration"],
    "default_credentials": ["weak_credentials", "default_password"],
    "admin_access": ["broken_access_control", "unauthorized_access"],
    "forged_feedback": ["broken_access_control", "authorization_bypass"],
    "captcha_bypass": ["broken_anti_automation", "captcha"],
}
