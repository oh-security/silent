import argparse
import base64
import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


# -----------------------------
# Time / Canonicalization / Hashing
# -----------------------------
def utc_now_z() -> str:
    """
    ISO-8601 UTC timestamp with Z suffix.
    Example: 2026-01-25T11:34:53Z
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonicalize_json(data: Dict[str, Any]) -> Tuple[bytes, int]:
    """
    Canonicalize JSON deterministically:
      - sorted keys
      - UTF-8
      - no whitespace (separators)
    Returns (canonical_bytes, size_bytes).
    """
    canonical_str = json.dumps(
        data,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    b = canonical_str.encode("utf-8")
    return b, len(b)


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def make_certificate_id(created_at_utc: str) -> str:
    """
    Human-friendly ID:
      sc_YYYYMMDDTHHMMSSZ_<uuid8>
    created_at_utc example: 2026-01-25T12:21:12Z
    """
    compact = created_at_utc.replace("-", "").replace(":", "")
    short = uuid.uuid4().hex[:8]
    return f"sc_{compact}_{short}"


# -----------------------------
# Capture Stub (AWS later)
# -----------------------------
def capture_observable_state_stub() -> Tuple[Dict[str, Any], str, str]:
    """
    Placeholder for the real AWS IAM capture.

    Returns:
      (normalized_state, started_at_utc, finished_at_utc)

    Note:
      - Keep it deliberately boring.
      - Replace 'state' with real AWS IAM collection later.
    """
    started = utc_now_z()

    # Minimal observable state (stub)
    state = {"example": "this represents observable state"}

    finished = utc_now_z()
    return state, started, finished


# -----------------------------
# Certificate Construction
# -----------------------------
@dataclass
class SilentConfig:
    provider: str = "aws"
    domain: str = "iam"
    region: str = "global"
    account_id: Optional[str] = None

    actor_type: str = "human"
    actor_id: Optional[str] = None
    display_name: Optional[str] = None

    trigger_type: str = "manual"
    trigger_reason: Optional[str] = None

    tool_name: str = "silent"
    tool_version: str = "0.1.0"

    out_json_path: str = "certificate.json"
    also_write_payload: bool = False  # default False: keep certificate != data


def build_certificate(
    normalized_state: Dict[str, Any],
    collection_started_at_utc: str,
    collection_finished_at_utc: str,
    cfg: SilentConfig,
) -> Dict[str, Any]:
    created_at = utc_now_z()
    cert_id = make_certificate_id(created_at)

    canonical_bytes, size_bytes = canonicalize_json(normalized_state)
    digest = sha256_hex(canonical_bytes)

    # Optional identity fields are included only if provided (avoid unnecessary PII).
    created_by: Dict[str, Any] = {
        "actor_type": cfg.actor_type,
    }
    if cfg.actor_id:
        created_by["actor_id"] = cfg.actor_id
    if cfg.display_name:
        created_by["display_name"] = cfg.display_name

    trigger: Dict[str, Any] = {"trigger_type": cfg.trigger_type}
    if cfg.trigger_reason:
        trigger["trigger_reason"] = cfg.trigger_reason

    scope: Dict[str, Any] = {
        "provider": cfg.provider,
        "domain": cfg.domain,
        "region": cfg.region,
        "resources_included": ["iam:users", "iam:roles", "iam:policies"],
        "resources_excluded": ["secrets", "payloads", "content_bodies"],
    }
    if cfg.account_id:
        scope["account_id"] = cfg.account_id

    collection = {
        "read_only": True,
        "collector": {"name": cfg.tool_name, "version": cfg.tool_version},
        "collection_started_at_utc": collection_started_at_utc,
        "collection_finished_at_utc": collection_finished_at_utc,
    }

    certificate: Dict[str, Any] = {
        "silent_certificate_version": "1.0",
        "certificate_id": cert_id,
        "created_at_utc": created_at,
        "created_by": created_by,
        "trigger": trigger,
        "scope": scope,
        "collection": collection,
        "data": {
            "format": "normalized_json",
            "canonicalization": "sorted_keys_utf8_no_whitespace",
            "sha256": digest,
            "size_bytes": size_bytes,
        },
        "disclaimer": {
            "statement": (
                "This certificate represents what was observable at the time of capture. "
                "No assessment, approval, or guarantee is implied."
            ),
            "intentionally_omits": [
                "risk_assessment",
                "recommendations",
                "compliance_judgment",
                "future_guarantees",
                "continuous_monitoring",
                "alerts_or_notifications",
            ],
        },
        "signature": {
            "method": "none",
            "note": (
                "Optional: cryptographic signing may be added by the consuming system "
                "without changing the meaning of this certificate."
            ),
        },
    }

    return certificate


def write_json(path: str, obj: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


# -----------------------------
# Optional Signing (Ed25519 detached)
# -----------------------------
def sig_path_for(cert_path: str) -> str:
    p = Path(cert_path)
    if p.suffix.lower() == ".json":
        return str(p.with_suffix(".sig.json"))
    return str(p) + ".sig.json"


def sign_certificate_detached(
    cert_json_path: str,
    sk_b64_path: str = "keys/silent_ed25519_sk.b64",
    out_sig_path: Optional[str] = None,
) -> str:
    """
    Creates detached signature JSON for the *canonical JSON* of certificate.json.
    Returns the signature file path.
    """
    try:
        from nacl.signing import SigningKey
    except Exception:
        raise SystemExit("PyNaCl not installed. Run: python -m pip install pynacl")

    cert_p = Path(cert_json_path)
    if not cert_p.exists():
        raise SystemExit(f"certificate not found: {cert_json_path}")

    sk_p = Path(sk_b64_path)
    if not sk_p.exists():
        raise SystemExit(f"private key not found: {sk_b64_path} (run tools/gen_keys.py first)")

    # Load & canonicalize the certificate JSON (not the pretty-printed bytes on disk)
    cert_obj = json.loads(cert_p.read_text(encoding="utf-8"))
    cert_bytes, _ = canonicalize_json(cert_obj)

    sk_b64 = sk_p.read_text(encoding="utf-8").strip()
    sk = SigningKey(base64.b64decode(sk_b64))

    signature = sk.sign(cert_bytes).signature
    sig_b64 = base64.b64encode(signature).decode("ascii")

    key_id = "ed25519:" + hashlib.sha256(sk.verify_key.encode()).hexdigest()[:16]

    sig_doc = {
        "silent_signature_version": "1.0",
        "algorithm": "ed25519",
        "canonicalization": "json(sort_keys=true,separators=(',',':'),utf8)",
        "signed_artifact": str(cert_p.name),
        "certificate_sha256": sha256_hex(cert_bytes),
        "signature_b64": sig_b64,
        "key_id": key_id,
    }

    sig_out = Path(out_sig_path) if out_sig_path else Path(sig_path_for(cert_json_path))
    sig_out.write_text(json.dumps(sig_doc, indent=2) + "\n", encoding="utf-8")
    return str(sig_out)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="silent",
        description="SILENT 窶・a prepared silence. Generates a non-binding certificate of what was observable.",
    )
    parser.add_argument("--account-id", default=None, help="AWS account id (optional).")
    parser.add_argument("--actor-id", default=None, help="Actor id (optional).")
    parser.add_argument("--display-name", default=None, help="Actor display name (optional).")
    parser.add_argument("--reason", default=None, help="Optional free-text reason for the manual trigger.")
    parser.add_argument("--out", default="certificate.json", help="Output path for certificate JSON.")
    parser.add_argument(
        "--write-payload",
        action="store_true",
        help="Also write the normalized payload to payload.normalized.json (debug only; not recommended).",
    )

    # NEW: optional signing
    parser.add_argument(
        "--sign",
        action="store_true",
        help="Optionally create a detached Ed25519 signature (certificate.sig.json). Requires keys/silent_ed25519_sk.b64",
    )

    args = parser.parse_args()

    # Allow env overrides (optional)
    actor_id = args.actor_id or os.getenv("SILENT_ACTOR_ID")
    display_name = args.display_name or os.getenv("SILENT_DISPLAY_NAME")
    account_id = args.account_id or os.getenv("SILENT_AWS_ACCOUNT_ID")

    cfg = SilentConfig(
        account_id=account_id,
        actor_id=actor_id,
        display_name=display_name,
        trigger_reason=args.reason,
        out_json_path=args.out,
        also_write_payload=args.write_payload,
    )

    # Capture (stub for now)
    normalized_state, started_at, finished_at = capture_observable_state_stub()

    # Build certificate (now with real collection timestamps)
    cert = build_certificate(normalized_state, started_at, finished_at, cfg)

    # Write outputs
    write_json(cfg.out_json_path, cert)

    if cfg.also_write_payload:
        # Debug only; keep certificate separate from data by default.
        write_json("payload.normalized.json", normalized_state)

    print(f"{cfg.out_json_path} created")

    # Optional: sign the written certificate
    if args.sign:
        sig_out = sign_certificate_detached(cfg.out_json_path)
        print(f"{sig_out} created")


if __name__ == "__main__":
    main()
