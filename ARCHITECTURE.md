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

### 1. Scope Definition

The process begins with a user-defined scope.

This scope describes what the system declares it is responsible for observing at that moment.

Examples may include:

- provider
- domain
- included resources
- excluded resources

SILENT does not validate whether the scope is correct.

It records the declared boundary exactly as provided.

---

### 2. Certificate Generation

SILENT generates a single certificate file:

- `certificate.json`

This certificate contains the declared responsibility boundary at a specific moment in time.

The certificate is:

- point-in-time
- immutable in intent
- descriptive, not prescriptive

It does not contain analysis, judgement, or recommendations.

---

### 3. Optional Signing

SILENT may optionally generate a detached Ed25519 signature for the certificate.

Files:

- `certificate.json`
- `certificate.sig.json`

The signature provides **tamper evidence only**.

It does not:

- validate correctness
- approve the certificate
- guarantee security

---

### 4. Storage and Use

The generated certificate can be stored and attached to downstream systems such as:

- incident records
- audit evidence
- change review documentation
- post-incident review packages

SILENT itself does not perform workflow orchestration.

It produces a record that other systems may consume.

---

## Architectural Constraints

SILENT is intentionally constrained.

It has:

- no continuous monitoring
- no alerting
- no scoring
- no policy enforcement
- no automated remediation
- no external dependency requirement

These constraints are part of the architecture, not missing features.

They preserve the narrow role of SILENT:

**recording a declared responsibility boundary without interpreting it.**

---

## What SILENT Produces

SILENT produces a certificate that answers one question:

> What did the system declare it was responsible for observing at that time?

It does **not** answer:

- what actually happened
- whether the declaration was correct
- whether the system was secure
- what action should be taken next

---

## Relationship to Other Documents

- `README.md` explains what SILENT is and how to use it
- `SPEC.md` defines the certificate format
- `PHILOSOPHY.md` explains the design philosophy
- `ARCHITECTURE.md` explains how the system is structurally organized
