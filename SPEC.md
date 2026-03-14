# SILENT Certificate Specification

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

Example:

scope.provider
scope.domain
scope.resources_included
scope.resources_excluded
