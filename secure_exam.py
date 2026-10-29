#!/usr/bin/env python3
"""
secure_exam.py -- Secure examination-paper exchange (hybrid encryption + signature).

Built on the well-established `cryptography` library (no home-made primitives).

Scheme
------
  Key pairs   : RSA-4096 for the sender (faculty) and the recipient (coordinator).
                Private keys are stored as passphrase-encrypted PKCS#8 PEM, mode 0600.
  Encryption  : a FRESH random AES-256 session key and a FRESH random 96-bit nonce are
                generated for every encryption; the paper is encrypted with AES-256-GCM.
                The package metadata is bound to the ciphertext as GCM Additional
                Authenticated Data (AAD).
  Key wrap    : session key encrypted with the recipient's RSA public key,
                RSA-OAEP (MGF1-SHA256, label = None, hash = SHA-256).
  Signature   : the COMPLETE package (format, version, metadata, wrapped key, nonce,
                ciphertext, tag) is signed with the sender's RSA private key,
                RSA-PSS (MGF1-SHA256, SHA-256, 32-byte salt).
  Receiving   : 1. parse + sanity-check the package
                2. verify the signature with the TRUSTED copy of the sender's public key
                3. replay check (optional ledger)
                4. unwrap the session key with the recipient's private key
                5. AES-GCM decrypt (verifies the authentication tag)
                6. only now is plaintext released / written to disk.
                Any failure raises a SecureExamError subclass and NO plaintext is released.

Command line
------------
  python secure_exam.py keygen  --name sender    --out-dir sender/keys
  python secure_exam.py keygen  --name recipient --out-dir recipient/keys
  python secure_exam.py fingerprint --public-key recipient/keys/recipient_public.pem
  python secure_exam.py encrypt --input paper.txt --output paper.exampkg \
        --sender-private sender/keys/sender_private.pem \
        --recipient-public sender/trusted/recipient_public.pem
  python secure_exam.py decrypt --package paper.exampkg --out-dir recipient/decrypted \
        --recipient-private recipient/keys/recipient_private.pem \
        --sender-public recipient/trusted/sender_public.pem --ledger recipient/ledger.json

Key passphrases are read from the environment variable named by --passphrase-env
(default EXAM_KEY_PASSPHRASE) or, if unset, prompted for without echo.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- parameters
RSA_KEY_BITS = 4096            # default key size (large)
MIN_RSA_BITS = 3072            # refuse to use / load anything smaller
AES_KEY_BITS = 256
GCM_NONCE_BYTES = 12           # 96-bit nonce, the size GCM is designed for
GCM_TAG_BYTES = 16             # 128-bit authentication tag
PSS_SALT_BYTES = 32            # = SHA-256 digest size
FORMAT_ID = "exampkg"
PACKAGE_VERSION = 1
MAX_PACKAGE_BYTES = 512 * 1024 * 1024
ALGORITHMS = {
    "symmetric": "AES-256-GCM",
    "key_wrap": "RSA-OAEP-SHA256",
    "signature": "RSA-PSS-SHA256",
}
_PACKAGE_FIELDS = {
    "format", "version", "metadata", "encrypted_session_key",
    "nonce", "ciphertext", "tag", "signature",
}


# --------------------------------------------------------------------------- errors
class SecureExamError(Exception):
    """Base class: the package/key was rejected and no plaintext was released."""


class KeyLoadError(SecureExamError):
    """A key file could not be loaded (corrupt, wrong passphrase, too small, wrong type)."""


class PackageFormatError(SecureExamError):
    """The package is malformed or uses an unsupported format/algorithm suite."""


class SignatureVerificationError(SecureExamError):
    """Digital signature invalid: package altered, or not signed by the trusted sender."""


class ReplayError(SecureExamError):
    """A package with this ID has already been accepted."""


class SessionKeyError(SecureExamError):
    """The AES session key could not be recovered with the supplied private key."""


class IntegrityError(SecureExamError):
    """AES-GCM authentication failed: ciphertext / tag / nonce / metadata were altered."""


# --------------------------------------------------------------------------- helpers
def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        raise PackageFormatError(f"Field '{field}' must be a base64 string.")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        raise PackageFormatError(f"Field '{field}' is not valid base64.") from None


def _canonical(obj: Any) -> bytes:
    """Deterministic JSON encoding: identical bytes on sender and recipient."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _oaep() -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(), label=None)


def _pss() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=PSS_SALT_BYTES)


def key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """SHA-256 of the DER SubjectPublicKeyInfo -- compare out-of-band when exchanging keys."""
    der = public_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_filename(name: str) -> str:
    """Strip any directory part so a package can never write outside the output folder."""
    base = os.path.basename(name.replace("\\", "/"))
    if base in ("", ".", "..") or "\x00" in base:
        raise PackageFormatError("Package contains an unsafe original filename.")
    return base


# --------------------------------------------------------------------------- key management
def generate_rsa_keypair(bits: int = RSA_KEY_BITS) -> rsa.RSAPrivateKey:
    if bits < MIN_RSA_BITS:
        raise ValueError(f"RSA key size must be at least {MIN_RSA_BITS} bits.")
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _write_file(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(path, mode)  # also tightens a pre-existing file


def save_private_key(key: rsa.RSAPrivateKey, path: str | Path, passphrase: bytes) -> None:
    """Passphrase-encrypted PKCS#8 PEM, owner-read/write only (0600)."""
    if not passphrase:
        raise ValueError("A non-empty passphrase is required to store a private key.")
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    _write_file(Path(path), pem, 0o600)


def save_public_key(key: rsa.RSAPublicKey, path: str | Path) -> None:
    pem = key.public_bytes(serialization.Encoding.PEM,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    _write_file(Path(path), pem, 0o644)


def _require_strong_rsa(key: Any, path: str | Path) -> Any:
    if not isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        raise KeyLoadError(f"{path}: not an RSA key.")
    if key.key_size < MIN_RSA_BITS:
        raise KeyLoadError(f"{path}: RSA key is only {key.key_size} bits (minimum {MIN_RSA_BITS}).")
    return key


def load_private_key(path: str | Path, passphrase: bytes) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=passphrase)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise KeyLoadError(f"Cannot load private key '{path}': wrong passphrase or corrupt key file.") from None
    return _require_strong_rsa(key, path)


def load_public_key(path: str | Path) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise KeyLoadError(f"Cannot load public key '{path}': corrupt or unsupported key file.") from None
    return _require_strong_rsa(key, path)


def generate_keypair_files(name: str, out_dir: str | Path, passphrase: bytes,
                           bits: int = RSA_KEY_BITS) -> tuple[Path, Path]:
    out = Path(out_dir)
    key = generate_rsa_keypair(bits)
    priv_path, pub_path = out / f"{name}_private.pem", out / f"{name}_public.pem"
    save_private_key(key, priv_path, passphrase)
    save_public_key(key.public_key(), pub_path)
    return priv_path, pub_path


# --------------------------------------------------------------------------- sender side
def _signing_input(package: dict) -> bytes:
    """Bytes covered by the signature: EVERY top-level field except the signature itself."""
    return _canonical({k: v for k, v in package.items() if k != "signature"})


def build_package(plaintext: bytes, filename: str, sender_private: rsa.RSAPrivateKey,
                  recipient_public: rsa.RSAPublicKey) -> dict:
    """Encrypt + wrap key + sign. Fresh session key and nonce on every call."""
    session_key = AESGCM.generate_key(bit_length=AES_KEY_BITS)   # fresh random AES-256 key
    nonce = os.urandom(GCM_NONCE_BYTES)                          # fresh random 96-bit nonce

    metadata = {
        "package_id": str(uuid.uuid4()),
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "original_filename": _safe_filename(filename),
        "plaintext_size": len(plaintext),
        "sender_key_fingerprint": key_fingerprint(sender_private.public_key()),
        "recipient_key_fingerprint": key_fingerprint(recipient_public),
        "algorithms": dict(ALGORITHMS),
    }

    # AES-256-GCM; metadata is authenticated as AAD. cryptography returns ciphertext || tag.
    sealed = AESGCM(session_key).encrypt(nonce, plaintext, _canonical(metadata))
    ciphertext, tag = sealed[:-GCM_TAG_BYTES], sealed[-GCM_TAG_BYTES:]

    # Protect the session key with the recipient's public key (RSA-OAEP, SHA-256).
    encrypted_session_key = recipient_public.encrypt(session_key, _oaep())

    package = {
        "format": FORMAT_ID,
        "version": PACKAGE_VERSION,
        "metadata": metadata,
        "encrypted_session_key": _b64e(encrypted_session_key),
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
        "tag": _b64e(tag),
    }
    # Sign the COMPLETE package with RSA-PSS / SHA-256.
    package["signature"] = _b64e(sender_private.sign(_signing_input(package), _pss(), hashes.SHA256()))
    return package


def encrypt_file(input_path: str | Path, output_path: str | Path,
                 sender_private: rsa.RSAPrivateKey, recipient_public: rsa.RSAPublicKey) -> dict:
    src = Path(input_path)
    package = build_package(src.read_bytes(), src.name, sender_private, recipient_public)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(package, indent=2), encoding="utf-8")
    return package


# --------------------------------------------------------------------------- recipient side
def parse_package(raw: bytes) -> dict:
    """Step 1 -- structural checks only. Nothing here is trusted yet."""
    if len(raw) > MAX_PACKAGE_BYTES:
        raise PackageFormatError("Package is too large.")
    try:
        package = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise PackageFormatError("File is not a valid exam package (not parseable JSON).") from None
    if not isinstance(package, dict) or set(package) != _PACKAGE_FIELDS:
        raise PackageFormatError("Package has missing or unexpected fields.")
    if package["format"] != FORMAT_ID or package["version"] != PACKAGE_VERSION:
        raise PackageFormatError("Unsupported package format or version.")
    if not isinstance(package["metadata"], dict):
        raise PackageFormatError("Package metadata is malformed.")
    if len(_b64d(package["nonce"], "nonce")) != GCM_NONCE_BYTES:
        raise PackageFormatError("Nonce has the wrong length.")
    if len(_b64d(package["tag"], "tag")) != GCM_TAG_BYTES:
        raise PackageFormatError("Authentication tag has the wrong length.")
    for field in ("encrypted_session_key", "ciphertext", "signature"):
        _b64d(package[field], field)
    return package


def verify_signature(package: dict, sender_public: rsa.RSAPublicKey) -> None:
    """Step 2 -- authenticate the sender and detect ANY modification of the package."""
    signature = _b64d(package["signature"], "signature")
    try:
        sender_public.verify(signature, _signing_input(package), _pss(), hashes.SHA256())
    except InvalidSignature:
        hint = ""
        if package["metadata"].get("sender_key_fingerprint") != key_fingerprint(sender_public):
            hint = (" The package declares a different sender key fingerprint than the "
                    "trusted public key you supplied.")
        raise SignatureVerificationError(
            "Signature verification FAILED: the package was modified or was not signed "
            "by the trusted sender." + hint) from None


def _validate_metadata(md: dict) -> None:
    required = {"package_id": str, "created_utc": str, "original_filename": str,
                "plaintext_size": int, "sender_key_fingerprint": str,
                "recipient_key_fingerprint": str, "algorithms": dict}
    for name, typ in required.items():
        value = md.get(name)
        if not isinstance(value, typ) or isinstance(value, bool):
            raise PackageFormatError(f"Metadata field '{name}' is missing or malformed.")
    if md["algorithms"] != ALGORITHMS:
        raise PackageFormatError("Unsupported algorithm suite (possible downgrade attempt).")


def unwrap_session_key(package: dict, recipient_private: rsa.RSAPrivateKey) -> bytes:
    """Step 4 -- recover the AES session key with RSA-OAEP / SHA-256."""
    wrapped = _b64d(package["encrypted_session_key"], "encrypted_session_key")
    try:
        key = recipient_private.decrypt(wrapped, _oaep())
    except ValueError:
        hint = ""
        expected = package["metadata"].get("recipient_key_fingerprint")
        mine = key_fingerprint(recipient_private.public_key())
        if isinstance(expected, str) and expected != mine:
            hint = (f" This package was encrypted for a different recipient key "
                    f"(expected fingerprint {expected[:16]}..., this key is {mine[:16]}...).")
        raise SessionKeyError("Session-key recovery FAILED: this private key cannot decrypt "
                              "the session key." + hint) from None
    if len(key) != AES_KEY_BITS // 8:
        raise SessionKeyError("Recovered session key has an unexpected length.")
    return key


def decrypt_payload(package: dict, session_key: bytes) -> bytes:
    """Step 5 -- AES-256-GCM decrypt. The tag covers ciphertext, nonce AND metadata (AAD)."""
    nonce = _b64d(package["nonce"], "nonce")
    ciphertext = _b64d(package["ciphertext"], "ciphertext")
    tag = _b64d(package["tag"], "tag")
    try:
        return AESGCM(session_key).decrypt(nonce, ciphertext + tag, _canonical(package["metadata"]))
    except InvalidTag:
        raise IntegrityError("AES-GCM authentication FAILED: ciphertext, tag, nonce or metadata "
                             "has been altered.") from None


def verify_and_decrypt(package_bytes: bytes, recipient_private: rsa.RSAPrivateKey,
                       sender_public: rsa.RSAPublicKey,
                       seen_package_ids: Iterable[str] = ()) -> tuple[dict, bytes]:
    """Run every check in order; return (metadata, plaintext) only if ALL succeed."""
    package = parse_package(package_bytes)                 # 1. structure
    verify_signature(package, sender_public)               # 2. sender authenticity + integrity
    metadata = package["metadata"]
    _validate_metadata(metadata)                           # 3. (now authenticated) metadata sanity
    if metadata["package_id"] in set(seen_package_ids):
        raise ReplayError("Package was already accepted earlier (replay attempt rejected).")
    session_key = unwrap_session_key(package, recipient_private)   # 4. key recovery
    plaintext = decrypt_payload(package, session_key)              # 5. GCM tag check + decrypt
    if len(plaintext) != metadata["plaintext_size"]:
        raise IntegrityError("Decrypted size does not match the signed metadata.")
    return metadata, plaintext                             # 6. only now is plaintext released


# ---- replay ledger (recipient side; fails closed if the ledger is unreadable)
def _load_ledger(path: str | Path | None) -> set[str]:
    if path is None or not Path(path).exists():
        return set()
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
            raise ValueError
        return set(data)
    except ValueError:
        raise SecureExamError(f"Replay ledger '{path}' is corrupt; refusing to continue.") from None


def _record_in_ledger(path: str | Path, package_id: str) -> None:
    ids = sorted(_load_ledger(path) | {package_id})
    _write_file(Path(path), json.dumps(ids, indent=2).encode("utf-8"), 0o600)


def decrypt_file(package_path: str | Path, recipient_private: rsa.RSAPrivateKey,
                 sender_public: rsa.RSAPublicKey, out_dir: str | Path,
                 ledger_path: str | Path | None = None) -> tuple[Path, dict]:
    """Verify + decrypt a package file; write the plaintext ONLY after every check passed."""
    src = Path(package_path)
    if src.stat().st_size > MAX_PACKAGE_BYTES:
        raise PackageFormatError("Package is too large.")
    metadata, plaintext = verify_and_decrypt(
        src.read_bytes(), recipient_private, sender_public, _load_ledger(ledger_path))

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    target = out / _safe_filename(metadata["original_filename"])
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise SecureExamError(f"Refusing to overwrite existing file '{target}'.") from None
    with os.fdopen(fd, "wb") as fh:
        fh.write(plaintext)
    if ledger_path is not None:
        _record_in_ledger(ledger_path, metadata["package_id"])
    return target, metadata


# --------------------------------------------------------------------------- CLI
def _passphrase(env_name: str, prompt: str, confirm: bool = False) -> bytes:
    value = os.environ.get(env_name)
    if value:
        return value.encode("utf-8")
    first = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repeat passphrase: ") != first:
        raise SecureExamError("Passphrases do not match.")
    return first.encode("utf-8")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Secure examination-paper exchange "
                                            "(AES-GCM + RSA-OAEP + RSA-PSS).")
    p.add_argument("--passphrase-env", default="EXAM_KEY_PASSPHRASE",
                   help="environment variable holding the private-key passphrase")
    sub = p.add_subparsers(dest="command", required=True)

    k = sub.add_parser("keygen", help="generate an RSA key pair")
    k.add_argument("--name", required=True)
    k.add_argument("--out-dir", required=True)
    k.add_argument("--bits", type=int, default=RSA_KEY_BITS)

    f = sub.add_parser("fingerprint", help="print a public key's SHA-256 fingerprint")
    f.add_argument("--public-key", required=True)

    e = sub.add_parser("encrypt", help="encrypt + sign an exam paper (sender)")
    e.add_argument("--input", required=True)
    e.add_argument("--output", required=True)
    e.add_argument("--sender-private", required=True)
    e.add_argument("--recipient-public", required=True)

    d = sub.add_parser("decrypt", help="verify + decrypt an exam package (recipient)")
    d.add_argument("--package", required=True)
    d.add_argument("--out-dir", required=True)
    d.add_argument("--recipient-private", required=True)
    d.add_argument("--sender-public", required=True)
    d.add_argument("--ledger", default=None, help="replay ledger file (recommended)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "keygen":
            pw = _passphrase(args.passphrase_env, "New private-key passphrase: ", confirm=True)
            priv, pub = generate_keypair_files(args.name, args.out_dir, pw, args.bits)
            print(f"Private key (encrypted, 0600): {priv}\nPublic key: {pub}")
            print(f"Public-key fingerprint (SHA-256): {key_fingerprint(load_public_key(pub))}")
        elif args.command == "fingerprint":
            print(key_fingerprint(load_public_key(args.public_key)))
        elif args.command == "encrypt":
            pw = _passphrase(args.passphrase_env, "Sender private-key passphrase: ")
            pkg = encrypt_file(args.input, args.output,
                               load_private_key(args.sender_private, pw),
                               load_public_key(args.recipient_public))
            print(f"Encrypted and signed -> {args.output} (package {pkg['metadata']['package_id']})")
        elif args.command == "decrypt":
            pw = _passphrase(args.passphrase_env, "Recipient private-key passphrase: ")
            path, md = decrypt_file(args.package, load_private_key(args.recipient_private, pw),
                                    load_public_key(args.sender_public), args.out_dir, args.ledger)
            print("ACCEPTED: signature valid, session key recovered, GCM tag valid.")
            print(f"Recovered '{md['original_filename']}' ({md['plaintext_size']} bytes) -> {path}")
        return 0
    except SecureExamError as exc:
        print(f"REJECTED [{type(exc).__name__}]: {exc}\nNo plaintext was released.", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
