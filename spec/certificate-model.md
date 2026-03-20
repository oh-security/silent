# SILENT Certificate Data Model

This document describes the minimal data model for a SILENT certificate.

## Core Fields

A SILENT certificate MUST include the following fields:

- `silent_certificate_version`
- `created_at_utc`
- `scope`

## Example

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

## Interpretation

A SILENT certificate records the declared responsibility boundary at the time of issuance.

It describes what a system stated it was responsible for observing.

A certificate does not validate correctness, completeness, or real system behavior.

---
