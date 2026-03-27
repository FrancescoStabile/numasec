---
name: authentication-testing
description: JWT, OAuth, session management, and credential testing techniques
---

# Authentication Testing Guide

## JWT (JSON Web Tokens)

### Common Vulnerabilities

**Algorithm Confusion (CVE-2015-9235)**
- Change `"alg": "RS256"` to `"alg": "HS256"` → sign with the public key
- Change `"alg": "RS256"` to `"alg": "none"` → remove signature entirely
- Tool: `auth_test` with `jwt_checks: true`

**Weak Signing Secret**
- Brute force HMAC secret with common wordlists
- Check for default secrets: `secret`, `password`, `jwt_secret`, `changeme`
- Tool: `auth_test` performs dictionary attack on JWT secret

**Missing Claims Validation**
- Remove or modify `exp` (expiry) → use expired tokens
- Modify `sub` (subject) → impersonate other users
- Modify `role`/`admin` claims → privilege escalation
- Remove `aud` (audience) → cross-service token reuse

**Key Injection (JWK/JKU)**
- Inject `"jwk"` header with attacker-controlled key
- Set `"jku"` to attacker-controlled URL serving JWKS
- Tool: `auth_test` tests JWK/JKU injection

### Testing Steps
1. Decode JWT (base64url decode header.payload.signature)
2. Check algorithm — is it `none`, HS256 with RS256 key?
3. Check claims — exp, sub, aud, iss, role
4. Try modifying claims and re-signing
5. `auth_test target=<url> jwt_checks=true`

## OAuth 2.0

### Common Vulnerabilities

**Open Redirect in Authorization**
- Manipulate `redirect_uri` to leak authorization codes
- Test: `redirect_uri=https://attacker.com/callback`
- Test: `redirect_uri=https://legit.com.attacker.com`
- Test: `redirect_uri=https://legit.com/callback/../../../attacker`

**Authorization Code Theft**
- Missing PKCE → authorization code interception
- Code reuse → replay stolen authorization codes
- Missing state parameter → CSRF on OAuth flow

**Token Leakage**
- Implicit flow → tokens in URL fragment (Referer header leak)
- Token in query string → logged in server access logs
- Missing token binding → token theft via XSS

**Scope Escalation**
- Request higher scopes than granted
- Modify scope during token refresh

### Testing Steps
1. Map the OAuth flow (authorization code vs implicit vs client credentials)
2. Check `redirect_uri` validation strictness
3. Check for PKCE (S256 challenge)
4. Check state parameter presence and validation
5. `auth_test target=<url> oauth_checks=true`

## Session Management

### What to Test
- Session ID randomness (sufficient entropy?)
- Session fixation (can attacker set session ID before auth?)
- Session timeout (does it expire?)
- Secure cookie flags (HttpOnly, Secure, SameSite)
- Concurrent session handling
- Session invalidation on logout
- Session invalidation on password change

### Cookie Flags Checklist
- `HttpOnly` — prevents JavaScript access (XSS mitigation)
- `Secure` — only sent over HTTPS
- `SameSite=Strict` or `Lax` — CSRF mitigation
- `Path=/` — appropriate scope
- `Domain` — not overly broad

### Testing Steps
1. Login and capture session cookie
2. Check cookie attributes in Set-Cookie header
3. Test session fixation: set cookie before login, check if it changes
4. Test logout: does the session get invalidated server-side?
5. `auth_test target=<url>` — automated session checks

## Credential Testing

### Password Policy
- Minimum length (< 8 is weak)
- Complexity requirements (upper, lower, digit, special)
- Common password rejection
- Password history enforcement

### Brute Force / Credential Spray
- Test account lockout threshold
- Test rate limiting on login endpoint
- Credential spray: few passwords against many accounts
- Tool: `auth_test target=<url> spray=true credentials=[list]`

### Password Reset
- Predictable reset tokens
- Token expiration
- Token reuse
- User enumeration via reset flow
- Host header injection in reset emails

### Multi-Factor Authentication
- MFA bypass via direct API access
- MFA code brute force (no rate limit)
- Backup codes reuse
- MFA downgrade (remove MFA enrollment)

### Default Credentials
Common pairs to test:
- `admin:admin`, `admin:password`, `admin:123456`
- `root:root`, `root:toor`
- `test:test`, `user:user`
- Application-specific defaults (check `kb_search`)
