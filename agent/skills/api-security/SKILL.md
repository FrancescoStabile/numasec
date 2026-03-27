---
name: api-security
description: REST and GraphQL API security testing techniques
---

# API Security Testing Guide

## REST API Testing

### Enumeration
1. **Endpoint Discovery**: `crawl` + `dir_fuzz` with API-specific wordlists
2. **Documentation**: Check `/api/docs`, `/swagger.json`, `/openapi.json`, `/api-docs`
3. **Version Detection**: Try `/api/v1/`, `/api/v2/`, `/v1/`, older versions may lack security
4. **Method Testing**: For each endpoint, test GET, POST, PUT, PATCH, DELETE, OPTIONS

### Common Vulnerabilities

**Broken Object Level Authorization (BOLA / IDOR)**
- Change numeric IDs: `/api/users/123` → `/api/users/124`
- Change UUIDs: enumerate or predict patterns
- Mass assignment: send extra fields in PUT/PATCH requests
- Tool: `access_control_test target=<url>`

**Broken Function Level Authorization**
- Access admin endpoints as regular user: `/api/admin/users`
- HTTP method switching: GET allowed but POST/DELETE not checked
- Tool: `access_control_test` with role-based testing

**Excessive Data Exposure**
- API returns more data than the UI displays
- Sensitive fields in responses: password hashes, tokens, PII
- Check response bodies carefully for hidden data

**Rate Limiting**
- No rate limit on authentication endpoints
- No rate limit on expensive operations (search, export)
- Bypass: rotate IP headers (`X-Forwarded-For`, `X-Real-IP`)

**Mass Assignment**
- Send admin-only fields in user update: `{"role": "admin"}`
- Send internal fields: `{"verified": true}`, `{"balance": 99999}`
- Check API docs for writable vs read-only fields

### Testing Steps
1. `crawl target=<url>` — discover API endpoints
2. `dir_fuzz target=<url>/api/ wordlist=api` — find hidden endpoints
3. For each endpoint: test auth, authorization, input validation
4. `injection_test` on all parameters
5. `access_control_test` for IDOR/privilege escalation

## GraphQL Testing

### Introspection
```graphql
{__schema{types{name,fields{name,args{name,type{name}}}}}}
```
If introspection is enabled, map the entire schema.

### Common Vulnerabilities

**Introspection Enabled in Production**
- Full schema disclosure
- Reveals internal types, mutations, subscriptions
- Tool: GraphQL tester checks introspection automatically

**Injection via Variables**
- SQL injection through GraphQL variables
- NoSQL injection in resolver implementations
```graphql
query { user(id: "1' OR '1'='1") { name email } }
```

**Denial of Service**
- Deeply nested queries:
```graphql
{ user { friends { friends { friends { friends { name } } } } } }
```
- Alias-based batching:
```graphql
{ a1: user(id:1){name} a2: user(id:2){name} ... a1000: user(id:1000){name} }
```
- Missing query depth/complexity limits

**Authorization Bypass**
- Access mutations without authentication
- Access other users' data through relationships
- Subscription endpoints may bypass auth checks

**Batching Attacks**
- Combine multiple operations to bypass rate limiting
- Brute force via batched login mutations

### Testing Steps
1. Check introspection: `{__schema{queryType{name}}}`
2. If enabled, dump full schema
3. Test all queries and mutations for auth
4. Test input fields for injection
5. Test query depth limits
6. Tool: `injection_test target=<url>/graphql type=graphql`

## API Authentication

### Bearer Token Testing
- Remove `Authorization` header entirely
- Use expired token
- Use token from different user
- Use token from different environment (staging → production)
- Modify token payload (if JWT, see authentication-testing skill)

### API Key Testing
- Key in URL query string (logged in access logs)
- Key shared across environments
- Key with excessive permissions
- Missing key rotation

### Testing with tools
```
http_request url=<endpoint> method=GET headers={"Authorization": "Bearer <token>"}
http_request url=<endpoint> method=GET  # without auth — should be 401
```
