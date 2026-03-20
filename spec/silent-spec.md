# SILENT Responsibility Boundary Certificate Specification

Version 0.1

SILENT defines a minimal specification for recording declared responsibility boundaries.

SILENT records what a system declared it was responsible for observing at a specific moment in time.

It proves scope, not reality.

---

# SILENT Certificate Structure

SILENT certificates record a declared responsibility boundary.

They describe what a system stated it was responsible for observing at a specific moment.

---

## Fields

### silent_certificate_version

Version of the certificate format.

### created_at_utc

UTC timestamp of certificate generation.

### scope

Defines the declared observation boundary.

Example fields:

- scope.provider
- scope.domain
- scope.resources_included
- scope.resources_excluded

---

## Design Principles

Certificates MUST be:

- immutable
- self-contained
- non-binding
- descriptive

Certificates describe what a system **declared**, not what actually occurred.

---

## Optional Signing

Certificates MAY include an optional Ed25519 detached signature.

The signature provides tamper evidence only.

It does not guarantee correctness.
