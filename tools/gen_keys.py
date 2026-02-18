# tools/gen_keys.py
from nacl.signing import SigningKey
import base64
from pathlib import Path

def main() -> None:
    out = Path("keys")
    out.mkdir(exist_ok=True)

    sk = SigningKey.generate()
    vk = sk.verify_key

    # PRIVATE KEY: DO NOT COMMIT
    (out / "silent_ed25519_sk.b64").write_text(
        base64.b64encode(sk.encode()).decode("ascii") + "\n",
        encoding="utf-8"
    )

    # PUBLIC KEY: OK TO COMMIT
    (out / "silent_ed25519_pk.b64").write_text(
        base64.b64encode(vk.encode()).decode("ascii") + "\n",
        encoding="utf-8"
    )

    print("Generated keys:")
    print("  keys/silent_ed25519_sk.b64  (PRIVATE - do NOT commit)")
    print("  keys/silent_ed25519_pk.b64  (PUBLIC  - OK to commit)")

if __name__ == "__main__":
    main()
