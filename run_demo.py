#!/usr/bin/env python3
"""
run_demo.py -- simulate the secure exam-paper exchange on ONE computer using separate
sender / recipient / attacker folders, then run the workshop test scenarios.

    python run_demo.py            # writes simulation/ and test_results.txt

Folder layout created under ./simulation
    sender/     keys/ (sender key pair)       trusted/ (recipient PUBLIC key)   exam paper
    recipient/  keys/ (recipient key pair)    trusted/ (sender PUBLIC key)      decrypted/
    attacker/   keys/ (attacker key pair)     known/   (recipient public key the attacker saw)
    channel/    the UNTRUSTED medium: everything here can be read/modified/replaced
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import sys
import time
from pathlib import Path

import secure_exam as se

HERE = Path(__file__).resolve().parent
SIM = HERE / "simulation"
SENDER, RECIPIENT, ATTACKER, CHANNEL = (SIM / n for n in ("sender", "recipient", "attacker", "channel"))
RESULTS_FILE = HERE / "test_results.txt"

# Demo-only passphrases. In real use they are typed in (getpass) and never stored in code.
PW_SENDER, PW_RECIPIENT, PW_ATTACKER = (b"demo-sender-passphrase", b"demo-recipient-passphrase",
                                        b"demo-attacker-passphrase")

PAPER_NAME = "exam_paper_CS402.txt"
PAPER_TEXT = """\
=====================================================================
  INSTITUTE OF TECHNOLOGY  --  END-SEMESTER EXAMINATION  (CONFIDENTIAL)
  Course : CS402 Network Security            Duration : 3 hours
  Date   : 12 December 2026                  Max marks: 100
=====================================================================
Instructions: Answer ALL questions. Use of unauthorised material is prohibited.

Q1. (15 marks)  Explain the CIA triad. For each property give one attack and
                one cryptographic control that addresses it.

Q2. (20 marks)  Compare symmetric and asymmetric encryption. Why do real systems
                combine them (hybrid encryption)? Describe the role of a session key.

Q3. (20 marks)  AES-GCM provides authenticated encryption.
                (a) What are the nonce and the authentication tag used for?
                (b) What catastrophic failure occurs if a (key, nonce) pair is reused?

Q4. (15 marks)  Why is textbook RSA insecure? Explain what OAEP and PSS add, and why
                the signature must cover the ENTIRE encrypted package.

Q5. (15 marks)  A man-in-the-middle replaces a public key during key exchange.
                Describe the attack and how a trusted channel or fingerprint check stops it.

Q6. (15 marks)  Design a protocol for sending a confidential file over an untrusted network
                so that confidentiality, integrity and sender authentication all hold.

*** MODEL ANSWER KEY AVAILABLE ONLY TO THE EXAMINATION COORDINATOR ***
Secret marker: CS402-FINAL-9F3A-BLUE-HERON
""" + ("Appendix (padding to make the file non-trivial): " + "lorem ipsum dolor sit amet. " * 60 + "\n")

# --------------------------------------------------------------------------- logging
_log_fh = None


def log(msg: str = "") -> None:
    print(msg)
    if _log_fh:
        _log_fh.write(msg + "\n")
        _log_fh.flush()


results: list[tuple[str, str, bool]] = []


def record(tid: str, title: str, passed: bool, details: list[str]) -> None:
    results.append((tid, title, passed))
    log(f"[{'PASS' if passed else 'FAIL'}] {tid}  {title}")
    for line in details:
        log(f"         {line}")
    log()


def listing(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir()) if folder.exists() else []


# --------------------------------------------------------------------------- tamper helpers
def load_pkg(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def save_pkg(pkg: dict, path: Path) -> Path:
    path.write_text(json.dumps(pkg, indent=2), encoding="utf-8")
    return path


def flip_bit_b64(value: str) -> str:
    raw = bytearray(base64.b64decode(value))
    raw[len(raw) // 2] ^= 0x01                      # flip ONE bit in the middle
    return base64.b64encode(bytes(raw)).decode("ascii")


def make_tampered(good: Path, name: str, mutate) -> Path:
    pkg = load_pkg(good)
    mutate(pkg)
    return save_pkg(pkg, CHANNEL / name)


def expect_rejection(tid: str, title: str, expected_exc: type, action, out_dir: Path) -> None:
    """Run `action`; PASS only if it raises `expected_exc` AND no plaintext appeared."""
    before = listing(out_dir)
    try:
        action()
    except expected_exc as exc:
        leaked = listing(out_dir) != before
        record(tid, title, not leaked, [
            f"Outcome : REJECTED with {type(exc).__name__}",
            f"Message : {exc}",
            f"Plaintext released: {'YES  <-- BUG' if leaked else 'no'}",
        ])
    except Exception as exc:  # wrong kind of failure
        record(tid, title, False, [f"Unexpected {type(exc).__name__}: {exc}"])
    else:
        record(tid, title, False, ["Package was ACCEPTED -- it should have been rejected!"])


# --------------------------------------------------------------------------- main flow
def main() -> int:
    global _log_fh
    if SIM.exists():
        shutil.rmtree(SIM)
    for d in (SENDER, RECIPIENT, ATTACKER, CHANNEL):
        d.mkdir(parents=True)
    _log_fh = open(RESULTS_FILE, "w", encoding="utf-8")

    log("=" * 78)
    log(" SECURE EXAMINATION-PAPER EXCHANGE  --  simulation and test report")
    log(f" Run: {time.strftime('%Y-%m-%d %H:%M:%S')}   Python {sys.version.split()[0]}")
    log("=" * 78)
    log()

    # ---- SETUP: key generation, trusted public-key exchange ------------------------------
    log("SETUP  Generating RSA-%d key pairs (sender, recipient, attacker) ..." % se.RSA_KEY_BITS)
    t0 = time.time()
    s_priv_p, s_pub_p = se.generate_keypair_files("sender", SENDER / "keys", PW_SENDER)
    r_priv_p, r_pub_p = se.generate_keypair_files("recipient", RECIPIENT / "keys", PW_RECIPIENT)
    a_priv_p, a_pub_p = se.generate_keypair_files("attacker", ATTACKER / "keys", PW_ATTACKER)
    log(f"       done in {time.time() - t0:.1f} s")

    # Public keys exchanged through a TRUSTED channel (simulated by a copy).
    (SENDER / "trusted").mkdir()
    (RECIPIENT / "trusted").mkdir()
    (ATTACKER / "known").mkdir()
    shutil.copy(r_pub_p, SENDER / "trusted" / "recipient_public.pem")
    shutil.copy(s_pub_p, RECIPIENT / "trusted" / "sender_public.pem")
    shutil.copy(r_pub_p, ATTACKER / "known" / "recipient_public.pem")  # public keys are public

    sender_priv = se.load_private_key(s_priv_p, PW_SENDER)
    recipient_priv = se.load_private_key(r_priv_p, PW_RECIPIENT)
    attacker_priv = se.load_private_key(a_priv_p, PW_ATTACKER)
    recipient_pub_at_sender = se.load_public_key(SENDER / "trusted" / "recipient_public.pem")
    sender_pub_at_recipient = se.load_public_key(RECIPIENT / "trusted" / "sender_public.pem")
    attacker_pub = se.load_public_key(a_pub_p)

    # Sample input: the exam paper sits in the sender's folder.
    paper_path = SENDER / PAPER_NAME
    paper_path.write_text(PAPER_TEXT, encoding="utf-8")
    original = paper_path.read_bytes()

    ATTACK_OUT = RECIPIENT / "attack_attempts_output"      # must stay EMPTY in every failure test
    ATTACK_OUT.mkdir()
    GOOD_OUT = RECIPIENT / "decrypted"
    LEDGER = RECIPIENT / "replay_ledger.json"

    # ---- T0: key generation and storage --------------------------------------------------
    details, ok = [], True
    for label, priv_path, pub_path, priv in (("sender", s_priv_p, s_pub_p, sender_priv),
                                             ("recipient", r_priv_p, r_pub_p, recipient_priv),
                                             ("attacker", a_priv_p, a_pub_p, attacker_priv)):
        mode = oct(os.stat(priv_path).st_mode & 0o777)
        encrypted = b"BEGIN ENCRYPTED PRIVATE KEY" in priv_path.read_bytes()
        fp = se.key_fingerprint(priv.public_key())

        if os.name == "posix":
            permission_ok = mode == "0o600"
        else:
            # Windows uses ACLs instead of POSIX permission bits.
            permission_ok = True
        ok &= priv.key_size == 4096 and permission_ok and encrypted
        details.append(f"{label:9s}: {priv.key_size}-bit RSA | private key file mode {mode}, "
                       f"passphrase-encrypted={encrypted} | pub fingerprint {fp[:24]}...")
    record("T0", "Key generation: separate RSA-4096 pairs, private keys stored encrypted (0600)", ok, details)

    # ---- T1: authorised recipient recovers the original ----------------------------------
    good_pkg_path = CHANNEL / "exam_paper_CS402.exampkg"
    pkg = se.encrypt_file(paper_path, good_pkg_path, sender_priv, recipient_pub_at_sender)
    pkg_bytes = good_pkg_path.read_bytes()
    marker_visible = b"CS402-FINAL-9F3A-BLUE-HERON" in pkg_bytes or b"END-SEMESTER" in pkg_bytes
    out_path, md = se.decrypt_file(good_pkg_path, recipient_priv, sender_pub_at_recipient,
                                   GOOD_OUT, LEDGER)
    recovered = out_path.read_bytes()
    ok = recovered == original and not marker_visible
    record("T1", "Authorised recipient recovers the original file", ok, [
        f"Original  : {paper_path.name}  {len(original)} bytes  SHA-256 {se.sha256_hex(original)[:32]}...",
        f"Package   : {good_pkg_path.name}  {len(pkg_bytes)} bytes  (package_id {md['package_id']})",
        f"Recovered : {out_path.relative_to(SIM)}  SHA-256 {se.sha256_hex(recovered)[:32]}...",
        f"Byte-identical to original: {recovered == original}",
        f"Confidentiality check - exam text visible inside package: {marker_visible}",
    ])

    # ---- T2: attacker modifies ciphertext / metadata / signature / other fields ----------
    def attempt(path: Path):
        return lambda: se.decrypt_file(path, recipient_priv, sender_pub_at_recipient, ATTACK_OUT)

    def mut_cipher(p): p["ciphertext"] = flip_bit_b64(p["ciphertext"])
    def mut_meta_name(p): p["metadata"]["original_filename"] = "answer_key_stolen.txt"
    def mut_meta_time(p): p["metadata"]["created_utc"] = "2026-12-31T23:59:59Z"
    def mut_sig(p): p["signature"] = flip_bit_b64(p["signature"])
    def mut_key(p): p["encrypted_session_key"] = flip_bit_b64(p["encrypted_session_key"])
    def mut_nonce(p): p["nonce"] = flip_bit_b64(p["nonce"])
    def mut_tag(p): p["tag"] = flip_bit_b64(p["tag"])

    for tid, title, name, mut in (
        ("T2a", "Attacker flips ONE bit of the ciphertext", "tampered_ciphertext.exampkg", mut_cipher),
        ("T2b", "Attacker edits metadata (original_filename)", "tampered_metadata_filename.exampkg", mut_meta_name),
        ("T2c", "Attacker edits metadata (created_utc timestamp)", "tampered_metadata_time.exampkg", mut_meta_time),
        ("T2d", "Attacker flips ONE bit of the signature", "tampered_signature.exampkg", mut_sig),
        ("T2e", "Attacker flips ONE bit of the wrapped session key", "tampered_session_key.exampkg", mut_key),
        ("T2f", "Attacker flips ONE bit of the nonce", "tampered_nonce.exampkg", mut_nonce),
        ("T2g", "Attacker flips ONE bit of the GCM tag", "tampered_tag.exampkg", mut_tag),
    ):
        expect_rejection(tid, title, se.SignatureVerificationError,
                         attempt(make_tampered(good_pkg_path, name, mut)), ATTACK_OUT)

    # T2h: attacker replaces the package with a complete, well-formed one of their own.
    att_known_pub = se.load_public_key(ATTACKER / "known" / "recipient_public.pem")
    forged = se.build_package(b"FAKE EXAM PAPER - all students get full marks\n", PAPER_NAME,
                              attacker_priv, att_known_pub)
    forged_path = save_pkg(forged, CHANNEL / "forged_by_attacker.exampkg")
    expect_rejection("T2h", "Attacker REPLACES the package with their own (validly encrypted + self-signed)",
                     se.SignatureVerificationError, attempt(forged_path), ATTACK_OUT)

    # T2i/T2j: defence in depth -- even if the signature check were skipped, GCM still detects it.
    base_pkg = load_pkg(good_pkg_path)
    session_key = se.unwrap_session_key(base_pkg, recipient_priv)   # simulate bypassed signature check
    bad_ct = json.loads(json.dumps(base_pkg)); mut_cipher(bad_ct)
    expect_rejection("T2i", "GCM layer alone: flipped ciphertext bit (signature check bypassed)",
                     se.IntegrityError, lambda: se.decrypt_payload(bad_ct, session_key), ATTACK_OUT)
    bad_md = json.loads(json.dumps(base_pkg)); mut_meta_name(bad_md)
    expect_rejection("T2j", "GCM layer alone: edited metadata is caught via AAD (signature check bypassed)",
                     se.IntegrityError, lambda: se.decrypt_payload(bad_md, session_key), ATTACK_OUT)

    # ---- T3: incorrect private key --------------------------------------------------------
    expect_rejection("T3a", "Recipient decrypts with an INCORRECT private key (attacker's key)",
                     se.SessionKeyError,
                     lambda: se.decrypt_file(good_pkg_path, attacker_priv, sender_pub_at_recipient, ATTACK_OUT),
                     ATTACK_OUT)
    expect_rejection("T3b", "Correct key file but WRONG passphrase -> private key cannot even be loaded",
                     se.KeyLoadError, lambda: se.load_private_key(r_priv_p, b"guessed-wrong-passphrase"),
                     ATTACK_OUT)

    # ---- T4: incorrect sender public key -------------------------------------------------
    expect_rejection("T4", "Signature verification with an INCORRECT sender public key",
                     se.SignatureVerificationError,
                     lambda: se.decrypt_file(good_pkg_path, recipient_priv, attacker_pub, ATTACK_OUT),
                     ATTACK_OUT)

    # ---- T5: same file encrypted twice -> different packages -----------------------------
    p1_path = CHANNEL / "exam_paper_CS402_encryption1.exampkg"
    p2_path = CHANNEL / "exam_paper_CS402_encryption2.exampkg"
    p1 = se.encrypt_file(paper_path, p1_path, sender_priv, recipient_pub_at_sender)
    p2 = se.encrypt_file(paper_path, p2_path, sender_priv, recipient_pub_at_sender)
    fields = ("nonce", "encrypted_session_key", "ciphertext", "tag", "signature")
    all_differ = all(p1[f] != p2[f] for f in fields) and p1_path.read_bytes() != p2_path.read_bytes()
    _, pt1 = se.verify_and_decrypt(p1_path.read_bytes(), recipient_priv, sender_pub_at_recipient)
    _, pt2 = se.verify_and_decrypt(p2_path.read_bytes(), recipient_priv, sender_pub_at_recipient)
    ok = all_differ and pt1 == pt2 == original
    lines = [f"{f:22s}: run1 {se._b64d(p1[f], f).hex()[:20]}...  run2 {se._b64d(p2[f], f).hex()[:20]}...  "
             f"{'DIFFERENT' if p1[f] != p2[f] else 'SAME  <-- BUG'}" for f in fields]
    lines.append(f"{'whole package SHA-256':22s}: run1 {se.sha256_hex(p1_path.read_bytes())[:20]}...  "
                 f"run2 {se.sha256_hex(p2_path.read_bytes())[:20]}...")
    lines.append(f"Both packages decrypt to the same original paper: {pt1 == pt2 == original}")
    record("T5", "Same file encrypted twice produces different encrypted packages", ok, lines)

    # ---- T6 (extra): replay of an already-accepted package -------------------------------
    expect_rejection("T6", "Attacker REPLAYS the genuine package that was already accepted (T1)",
                     se.ReplayError,
                     lambda: se.decrypt_file(good_pkg_path, recipient_priv, sender_pub_at_recipient,
                                             ATTACK_OUT, LEDGER),
                     ATTACK_OUT)

    # ---- final: no plaintext ever leaked by failed attempts ------------------------------
    leaked = listing(ATTACK_OUT)
    record("T7", "No plaintext was ever written by any rejected attempt", leaked == [],
           [f"Contents of recipient/attack_attempts_output/: {leaked or 'empty'}",
            f"Contents of recipient/decrypted/ (legitimate only): {listing(GOOD_OUT)}"])

    # ---- summary ---------------------------------------------------------------------------
    passed = sum(1 for _, _, ok in results if ok)
    log("=" * 78)
    log(f" SUMMARY: {passed}/{len(results)} checks passed")
    for tid, title, ok in results:
        log(f"   {'PASS' if ok else 'FAIL'}  {tid:4s} {title}")
    log("=" * 78)
    log()
    log("Simulation folder contents (private keys are demo keys, passphrase-encrypted):")
    for p in sorted(SIM.rglob("*")):
        if p.is_file():
            log(f"   {str(p.relative_to(SIM)):62s} {p.stat().st_size:>8,d} bytes")
    _log_fh.close()
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
