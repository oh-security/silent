# tools/verify_signature.py
import json
import base64
import hashlib
from pathlib import Path
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

CERT_PATH = Path("certificate.json")
SIG_PATH  = Path("certificate.sig.json")
PK_PATH   = Path("keys/silent_ed25519_pk.b64")

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
        raise SystemExit("certificate.json not found.")
    if not SIG_PATH.exists():
        raise SystemExit("certificate.sig.json not found (run tools/sign_certificate.py).")
    if not PK_PATH.exists():
        raise SystemExit("public key not found: keys/silent_ed25519_pk.b64.")

    cert_obj = json.loads(CERT_PATH.read_text(encoding="utf-8"))
    sig_doc = json.loads(SIG_PATH.read_text(encoding="utf-8"))

    cert_bytes = canonical_json_bytes(cert_obj)

    expected_hash = sig_doc.get("certificate_sha256")
    got_hash = sha256_hex(cert_bytes)
    if expected_hash != got_hash:
        raise SystemExit(f"Hash mismatch! expected={expected_hash} got={got_hash}")

    pk_b64 = PK_PATH.read_text(encoding="utf-8").strip()
    vk = VerifyKey(base64.b64decode(pk_b64))

    # (任意だが事故防止に強い) 公開鍵が正しいか key_id でチェック
    calc_key_id = "ed25519:" + hashlib.sha256(vk.encode()).hexdigest()[:16]
    if sig_doc.get("key_id") != calc_key_id:
        raise SystemExit(f"Key mismatch! sig expects {sig_doc.get('key_id')} but public key is {calc_key_id}")

    sig = base64.b64decode(sig_doc["signature_b64"])

    try:
        vk.verify(cert_bytes, sig)
    except BadSignatureError:
        raise SystemExit("Bad signature!")

    print("OK: signature verified")

if __name__ == "__main__":
    main()
