# SILENT

**Keep the line of responsibility.**

SILENT records what a system said it was responsible for observing at a specific moment in time.

When incidents occur, SILENT shows what the system claimed responsibility for at that time.

---

## What SILENT Is

SILENT creates a **responsibility boundary certificate**.

It records what a system declared it was responsible for observing at a specific moment.

SILENT does not determine what actually happened.

It records **what the system said it was responsible for observing at that time.**

---

## Example

A security platform says it is responsible for observing:

- IAM users  
- IAM roles  
- IAM policies  

It does not observe:

- application data  
- external services  
- secrets outside its scope  

SILENT records this declared responsibility boundary at that moment.

If an incident occurs later, the certificate shows what the platform said it was responsible for observing at that time.

---

### Intuitive Example

A company signs a contract with a security provider.

The contract states:

"We are responsible for monitoring the cloud infrastructure."

It also states that the provider is **not responsible** for:

- application code  
- external services  
- systems outside the agreed scope  

Months later, an incident occurs.

The first question becomes:

*What was the provider responsible for at that time?*

SILENT records that declared boundary when it was stated,  
so the answer does not change later.

---

## Quick Start

> `python tools\gen_keys.py` is required only once per machine.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install pynacl
python tools\gen_keys.py
python silent.py --sign
python tools\verify_signature.py
```

---

## How SILENT Works

SILENT operates with a deliberately minimal flow.
1. A capture is manually triggered
2. A scope definition is provided
3. A certificate is generated and stored

There are:
- no background processes
- no continuous monitoring
- no automated decisions

Each certificate stands alone.

SILENT proves scope, not reality.

---

## Certificate Example

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
