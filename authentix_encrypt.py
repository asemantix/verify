#!/usr/bin/env python3
"""
authentix_encrypt.py — Encrypt a PDF for an Authentix Sign recipient.

Reads a .authentix-id kit file, extracts encryption_pk,
encrypts a PDF using ECIES (X25519 + HKDF-SHA3-256 + AES-256-GCM).
Produces a .authentix file identical to what authentix-core Rust produces.

Usage:
    python authentix_encrypt.py <kit.authentix-id> <document.pdf> [-o output.authentix]
"""

import argparse
import base64
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# ── Constants (must match authentix-core/src/crypto.rs) ──────────────────

SALT_ECIES = b"AUTHENTIX-ECIES-v1"
INFO_AES   = b"aes-256-gcm-key"


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def hkdf_derive(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    """HKDF-SHA3-256, 32-byte output — mirrors Rust hkdf_derive()."""
    hkdf = HKDF(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


def encrypt_for(encryption_pk_b64: str, pdf_bytes: bytes) -> str:
    """
    ECIES encryption — exact replica of crypto::encrypt_for() in Rust.

    Returns JSON string with:
      - ephemeral_pk  (base64)
      - pdf_encrypted (base64, nonce[12] || ciphertext+tag)
      - doc_hash      (base64, SHA3-256 of plaintext PDF)
    """
    # Decode recipient's X25519 public key
    enc_pk_bytes = base64.b64decode(encryption_pk_b64)
    assert len(enc_pk_bytes) == 32, f"encryption_pk must be 32 bytes, got {len(enc_pk_bytes)}"
    recipient_pk = X25519PublicKey.from_public_bytes(enc_pk_bytes)

    # Ephemeral keypair
    eph_sk = X25519PrivateKey.generate()
    eph_pk = eph_sk.public_key()
    eph_pk_bytes = eph_pk.public_bytes_raw()

    # Diffie-Hellman
    shared_secret = eph_sk.exchange(recipient_pk)

    # Derive AES-256 key
    aes_key = hkdf_derive(shared_secret, SALT_ECIES, INFO_AES)

    # AES-256-GCM encrypt
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, pdf_bytes, None)  # ciphertext includes 16-byte tag

    # doc_hash
    doc_hash = sha3_256(pdf_bytes)

    # Concatenate nonce + ciphertext (same as Rust: nonce_ct)
    nonce_ct = nonce + ciphertext

    payload = {
        "ephemeral_pk":  base64.b64encode(eph_pk_bytes).decode(),
        "pdf_encrypted": base64.b64encode(nonce_ct).decode(),
        "doc_hash":      base64.b64encode(doc_hash).decode(),
    }

    return json.dumps(payload)


def load_kit(kit_path: str) -> dict:
    """Load and validate an .authentix-id kit file."""
    with open(kit_path, "r", encoding="utf-8") as f:
        kit = json.load(f)

    # The kit has structure: { version, type:"identity", owner: { encryption_pk, ... } }
    if "owner" in kit:
        owner = kit["owner"]
    else:
        owner = kit  # fallback: flat structure

    epk = owner.get("encryption_pk")
    if not epk:
        print("ERROR: No encryption_pk found in kit file", file=sys.stderr)
        sys.exit(1)

    return kit, epk


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt a PDF for an Authentix Sign recipient"
    )
    parser.add_argument("kit", help="Path to .authentix-id kit file")
    parser.add_argument("pdf", help="Path to PDF file to encrypt")
    parser.add_argument("-o", "--output", help="Output .authentix file (default: <pdf-name>.authentix)")
    parser.add_argument("--ref", default="", help="Document reference (e.g. VENTE-2026-042)")
    parser.add_argument("--subject", default="Document chiffré", help="Document subject")
    parser.add_argument("--sender-name", default="Expéditeur externe", help="Sender display name")
    args = parser.parse_args()

    # Load kit
    kit, encryption_pk = load_kit(args.kit)
    owner = kit.get("owner", kit)
    owner_name = owner.get("name", "Unknown")
    print(f"Recipient: {owner_name}")
    print(f"encryption_pk: {encryption_pk[:12]}...{encryption_pk[-6:]}")

    # Load PDF
    with open(args.pdf, "rb") as f:
        pdf_bytes = f.read()
    print(f"PDF: {args.pdf} ({len(pdf_bytes):,} bytes)")
    print(f"PDF SHA3-256: {sha3_256(pdf_bytes).hex()[:16]}...")

    # Encrypt
    payload_json = encrypt_for(encryption_pk, pdf_bytes)

    # Auto-generate ref if not provided
    doc_ref = args.ref or f"DOC-{os.path.splitext(os.path.basename(args.pdf))[0].upper()}"

    # Wrap in .authentix document envelope
    envelope = {
        "version": 1,
        "type": "document",
        "ref": doc_ref,
        "subject": args.subject,
        "sender": {
            "name": args.sender_name,
            "signing_pk": "",
            "encryption_pk": "",
        },
        "recipient": {
            "name": owner_name,
            "encryption_pk": encryption_pk,
        },
        "payload": json.loads(payload_json),
        "created": "2026-04-16T12:00:00Z",
    }

    # Output
    if args.output:
        out_path = args.output
    else:
        base = os.path.splitext(os.path.basename(args.pdf))[0]
        out_path = os.path.join(os.path.dirname(args.pdf) or ".", f"{base}.authentix")

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2)

    print(f"\nOutput: {out_path}")
    print(f"Size: {os.path.getsize(out_path):,} bytes")
    print("Done.")


if __name__ == "__main__":
    main()
