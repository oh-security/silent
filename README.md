# SILENT

**Keep the line of responsibility.**

Responsibility boundary certificates for systems.

SILENT records what a system declared it was responsible for observing at a specific moment in time.

Logs record events.  
Configuration history records system state.

**SILENT records responsibility boundaries.**

SILENT proves scope, not reality.

---

# SILENT in 30 seconds

1. A system declares what it is responsible for observing.
2. SILENT records that declared boundary.
3. If an incident occurs later, the certificate shows what the system said it was responsible for at that time.

SILENT records **declared responsibility boundaries**, not system reality.

---

# What SILENT Does

SILENT generates a single **immutable certificate** describing:

- what a system claimed it was responsible for observing
- what was explicitly outside that responsibility
- when that responsibility boundary was declared

The certificate preserves the **declared observation boundary** that existed at that moment in time.

This record can later be referenced during:

- incident investigations
- security reviews
- audits
- compliance evidence collection

---

# Example

A security platform declares that it observes:

- IAM users  
- IAM roles  
- IAM policies  

It explicitly does **not** observe:

- application data  
- external services  
- secrets outside its scope  

SILENT records this declared responsibility boundary.

If an incident occurs later, the certificate shows **what the platform said it was responsible for observing at that time.**

---

# Intuitive Example

A company signs a contract with a security provider.

The contract states:

> We are responsible for monitoring the cloud infrastructure.

It explicitly excludes:

- application code  
- external services  
- systems outside the agreed scope  

Months later an incident occurs.

The investigation asks:

> What was the provider responsible for at that time?

SILENT preserves that declared boundary when it was stated so the answer cannot change later.

---

# Where SILENT Fits

Modern systems already record many things:

| System Type | Records |
|-------------|--------|
| Logs | what happened |
| Configuration history | what existed |
| Monitoring | what changed |
| Security tools | what might be risky |
| **SILENT** | what the system claimed responsibility for observing |

SILENT does not replace security or observability systems.

It records something different:

**declared responsibility boundaries.**

These certificates can later be referenced during:

- incident investigations
- audit reviews
- compliance evidence collection

---

# How SILENT Works

SILENT operates with a deliberately minimal flow.

1. A capture is manually triggered
2. A scope definition is provided
3. A certificate is generated and stored

Each certificate is independent.

There are:

- no background processes
- no continuous monitoring
- no automated decisions
- no external system dependencies

SILENT simply records the **declared observation boundary at that moment in time.**

---

# Certificate Example

```json
{
  "silent_certificate_version": "1.0",
  "created_at_utc": "2026-01-25T12:31:37Z",
  "scope": {
    "provider": "aws",
    "domain": "iam",
    "resources_included": [
      "iam:users",
      "iam:roles",
      "iam:policies"
    ],
    "resources_excluded": [
      "secrets",
      "payloads",
      "content_bodies"
    ]
  }
}
```

---

## Documentation

- [Philosophy](./PHILOSOPHY.md)
- [Specification](./SPEC.md)
- [Architecture](./ARCHITECTURE.md)
