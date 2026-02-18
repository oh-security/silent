# tools/sign_certificate.py
import json
import base64
import hashlib
from pathlib import Path
from nacl.signing import SigningKey

CERT_PATH = Path("certificate.json")
SIG_PATH  = Path("certificate.sig.json")
SK_PATH   = Path("keys/silent_ed25519_sk.b64")

def canonical_json_bytes(obj) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def main() -> None:
    if not CERT_PATH.exists():
        raise SystemExit("certificate.json not found (run silent.py first if it generates it).")

    if not SK_PATH.exists():
        raise SystemExit("private key not found: keys/silent_ed25519_sk.b64 (run tools/gen_keys.py first).")

    cert_obj = json.loads(CERT_PATH.read_text(encoding="utf-8"))
    cert_bytes = canonical_json_bytes(cert_obj)

    sk_b64 = SK_PATH.read_text(encoding="utf-8").strip()
    sk = SigningKey(base64.b64decode(sk_b64))

    signature = sk.sign(cert_bytes).signature
    sig_b64 = base64.b64encode(signature).decode("ascii")

    key_id = "ed25519:" + hashlib.sha256(sk.verify_key.encode()).hexdigest()[:16]

    sig_doc = {
        "silent_signature_version": "1.0",
        "algorithm": "ed25519",
        "canonicalization": "json(sort_keys=true,separators=(',',':'),utf8)",
        "signed_artifact": "certificate.json",
        "certificate_sha256": sha256_hex(cert_bytes),
        "signature_b64": sig_b64,
        "key_id": key_id
    }

    SIG_PATH.write_text(json.dumps(sig_doc, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote: {SIG_PATH}")

if __name__ == "__main__":
    main()
