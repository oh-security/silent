# SILENT

**SILENT is a prepared silence.**

SILENT does not detect, assess, or recommend.  
It does not judge risk, security, or compliance.

SILENT preserves what was observable by an organization  
at a specific moment in time — and nothing more.

It exists for when something happens.

SILENT is a responsibility boundary certificate: it records what the platform claimed to cover at that time.

---

## What SILENT Is

SILENT is a state snapshot tool.

It creates a single, immutable record that represents  
the limit of awareness at that moment.

It is designed to exist quietly,  
until it is needed.

---

## What SILENT Is Not

SILENT intentionally does **not**:

- Detect vulnerabilities
- Assess risk or severity
- Judge security posture
- Judge compliance
- Recommend actions
- Apply fixes
- Monitor continuously
- Alert or notify
- Score or rank environments
- Provide guarantees of safety

SILENT is **not**:

- A security scanner
- A monitoring system
- A dashboard
- An alerting tool
- A compliance product
- A decision engine

If SILENT appears to do any of the above,  
it is no longer SILENT.

---

## Why SILENT Exists

When incidents occur, the question is rarely only *what happened*.

More often, it is:

> What did you know at that time?

Logs and configuration histories provide facts.  
They show what existed.

SILENT exists to preserve something different:

**what was observable.**

It captures the boundary between  
what could be seen  
and what could not.

SILENT does not attempt to fill that gap.  
It records it.

### Why now (AI and autonomous systems)

As security platforms start relying more on AI for triage and automated decisions, it becomes harder to explain—after the fact—what the platform was actually responsible for. SILENT keeps a simple, immutable record of what was in scope (and what was explicitly out of scope) at a point in time, so incident reviews and audits stay defensible as systems become more autonomous.


---

## How SILENT Works

SILENT operates with a deliberately minimal flow.

- A capture is manually triggered.
- SILENT uses a user-defined snapshot of the target scope.
- A single certificate is generated and stored.

There are no background processes.  
There is no continuous execution.  
There are no automated decisions.  
There is no external system connection.

Each capture stands alone.

SILENT does not compare states, track changes over time,  
or interpret what it records.

It simply preserves what was observable, when it was observable.

SILENT proves scope, not reality.

## Optional Signing (Ed25519 Detached Signature)

SILENT supports an **optional**, detached Ed25519 signature for `certificate.json`.

This signature is **not a guarantee** and does not change the meaning of the certificate.
It only provides **tamper-evidence** (detects modification after issuance).

### Design Principles
- Signing is **optional** (consumers may ignore it)
- The private key is **never** committed to GitHub
- GitHub contains the **public key only**
- The signature provides tamper-evidence, not correctness or approval

### Files
- `certificate.json` — the certificate
- `certificate.sig.json` — detached signature metadata
- `keys/silent_ed25519_pk.b64` — public key (OK to commit)
- `keys/silent_ed25519_sk.b64` — private key (**DO NOT COMMIT**)

### Setup (Windows / PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install pynacl
```

---

## Optional: Asset Inventory Reference (CMDB)

SILENT does not integrate with CMDB systems.

However, the certificate may optionally include an `asset_id`
(and an `inventory_url`) provided by the consuming system,
so the record can be traced back during incident reviews and audits.

Example:

```json
"asset": {
  "asset_id": "CMDB-12345",
  "inventory_url": "https://..."
}
```

This does not change the meaning of SILENT.
It only makes the certificate easier to reference in real workflows.

---

## Design Principles

SILENT is governed by the following principles.  
They are not implementation details.  
They are constraints.

### Prepared Silence

SILENT prepares to say nothing,  
until something happens.

It does not attempt to prevent incidents,  
only to remain accurate when they are questioned.

---

### Non-Binding by Design

SILENT does not create approval,  
endorsement,  
or obligation.

Its records are descriptive,  
not prescriptive.

No action is implied by the existence of a certificate.

---

### Failure-Resistant

SILENT cannot fail silently,  
because it does not promise to act.

There are no alerts to miss,  
no scores to misinterpret,  
and no recommendations to follow.

Absence of a record is also a valid outcome.

---

### Minimal Surface Area

SILENT intentionally minimizes  
features,  
configuration,  
and scope.

A smaller surface reduces  
misinterpretation,  
misuse,  
and unintended responsibility.

---

### Founder-Independent

SILENT is designed to remain valid  
without ongoing interpretation.

Its meaning is fixed by design,  
not by explanation.

If SILENT requires ongoing interpretation,  
it has already failed.

