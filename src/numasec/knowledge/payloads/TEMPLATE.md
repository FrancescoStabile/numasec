# Template for Adding New Payloads

Copy this template to create new payload files.

---

## Example Payload Section

**Payload:** `' UNION SELECT NULL,NULL--`
**Use case:** Column enumeration for SQL injection
**Context:** URL parameter, POST data
**Bypass:** Encoding, comments
**Tags:** sqli, union, enumeration

---

## Alternative Format (Code Block)

You can also use code blocks:

```bash
' OR 1=1--
```

Both formats are supported by the parser!

---

## Tips

1. **Use descriptive section names** (##)
2. **Keep payloads atomic** (one technique per section)
3. **Add use case** (when to use this)
4. **Tag appropriately** (helps search)
5. **Test your payloads** (ensure they're valid)

---

## After Adding Payloads

Re-run population script:

```bash
cd src
python -m numasec.knowledge.seeds.populate
```

Your new payloads will be automatically embedded and searchable!
