# SILENT Model

SILENT defines a simple model for recording **declared responsibility boundaries**.

The model answers one question:

> What did a system declare it was responsible for observing at a specific moment in time?

SILENT does not attempt to determine what actually happened.

It records the **declared observation boundary** that existed at that moment.

---

# Core Concept

A SILENT certificate records three elements:

1. **Declaration**
2. **Observation Scope**
3. **Time**

Together these form a **responsibility boundary record**.

```
System declaration
        │
        ▼
Observation scope
        │
        ▼
Timestamp
        │
        ▼
SILENT certificate
```

---

# Model Components

## Declaration

A system states what it claims responsibility for observing.

Example:

```
This platform observes AWS IAM configuration.
```

The declaration may include explicit exclusions.

Example:

```
Application data is outside the observation scope.
```

SILENT records this declaration.

---

## Observation Scope

The scope defines **what the system claims it observes**.

Typical scope elements include:

- provider
- service domain
- resource types
- included resources
- excluded resources

Example:

```
provider: aws
domain: iam
resources_included:
  - iam:users
  - iam:roles
  - iam:policies
```

The scope defines the **responsibility boundary**.

---

## Time

Each certificate records the exact moment the declaration was captured.

```
created_at_utc
```

This timestamp anchors the declaration in time.

---

# Resulting Artifact

The result is a **SILENT certificate**.

A certificate is a structured record containing:

- declaration context
- observation scope
- timestamp

Example structure:

```
certificate
 ├─ version
 ├─ timestamp
 └─ scope
```

The certificate represents **what the system declared it was responsible for observing at that moment.**

---

# What the Model Does Not Do

The SILENT model intentionally does **not**:

- determine what actually happened
- validate security posture
- guarantee correctness
- approve configurations
- detect incidents

SILENT records **declared scope**, not system reality.

---

# Relationship to Other Systems

Different systems record different dimensions.

| System | Records |
|------|------|
| Logs | events |
| Configuration history | system state |
| Monitoring | changes |
| Security tools | risk indicators |
| **SILENT** | declared responsibility boundaries |

SILENT introduces a new dimension:

**responsibility scope recording**.

---

# Summary

SILENT defines a minimal model for preserving **declared responsibility boundaries**.

Each certificate answers one question:

> What did the system claim it was responsible for observing at that time?
