# SILENT Architecture

SILENT is intentionally small.

Its architecture is designed to preserve a **declared responsibility boundary** with as little interpretation as possible.

---

## High-Level Flow

```text
User-defined scope
        ↓
     SILENT
        ↓
certificate.json
        ↓
optional signature
        ↓
stored record
```

SILENT does not monitor continuously.
It does not connect to external systems.
It does not interpret what it records.

It simply turns a declared observation boundary into a durable certificate.

---

## Core Components

## 1. Scope Definition

The process begins with a user-defined scope.

This scope describes what the system declares it is responsible for observing at that moment.

Examples may include:

- provider
- domain
- included resources
- excluded resources

SILENT does not validate whether the scope is correct.

It records the declared boundary as provided.

## 2. Certificate Generation

SILENT generates a single certificate file:

- certificate.json

This certificate contains the declared responsibility boundary at a specific moment in time.

The certificate is:
- point-in-time
- immutable in intent
- descriptive, not prescriptive

It does not contain analysis, judgement, or recommendations.

## 3. Optional Signing

SILENT may optionally generate a detached Ed25519 signature for the certificate.

Files:

- certificate.json
- certificate.sig.json

The signature provides **tamper evidence only.**

It does not:

- validate correctnes
- approve the certificate
- guarantee security
