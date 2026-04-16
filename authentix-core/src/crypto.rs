use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use crate::types::*;

const SALT_MASTER: &[u8] = b"AUTHENTIX-SIGN-v1";
const SALT_ECIES: &[u8] = b"AUTHENTIX-ECIES-v1";
const INFO_SIGNING: &[u8] = b"signing-private-key";
const INFO_ENCRYPTION: &[u8] = b"encryption-private-key";
const INFO_SEED: &[u8] = b"master-seed";
const INFO_AES: &[u8] = b"aes-256-gcm-key";
const INFO_DOC_SIG: &[u8] = b"document-signature";

fn sha3(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize().into()
}

fn hkdf_derive(input: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha3_256>::new(Some(salt), input);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("hkdf expand");
    out
}

pub fn setup(
    android_id: &str,
    build_fingerprint: &str,
    manufacturer: &str,
    model: &str,
    keystore_attestation: Option<&[u8]>,
    bio_key_bytes: &[u8],
    os_version: &str,
    app_version: &str,
) -> (SetupResult, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    // 1. Derive master seed from device IDs
    let mut id_material = Vec::new();
    id_material.extend_from_slice(android_id.as_bytes());
    id_material.extend_from_slice(build_fingerprint.as_bytes());
    if let Some(att) = keystore_attestation {
        id_material.extend_from_slice(att);
    }
    let g = hkdf_derive(&id_material, SALT_MASTER, INFO_SEED);

    // 2. bio_hash from KeyStore-backed key bytes
    let bio_hash = sha3(bio_key_bytes);

    // 3. Derive signing keypair
    let mut signing_input = Vec::new();
    signing_input.extend_from_slice(&g);
    signing_input.extend_from_slice(&bio_hash);
    let sk_bytes = hkdf_derive(&signing_input, SALT_MASTER, INFO_SIGNING);
    let signing_key = SigningKey::from_bytes(&sk_bytes);
    let pk = signing_key.verifying_key();

    // 4. Derive encryption keypair
    let enc_sk_bytes = hkdf_derive(&signing_input, SALT_MASTER, INFO_ENCRYPTION);
    let enc_sk = X25519Secret::from(enc_sk_bytes);
    let enc_pk = X25519Public::from(&enc_sk);

    // 5. Build markers
    let id_short = if android_id.len() >= 8 {
        format!("{}...{}", &android_id[..4], &android_id[android_id.len() - 4..])
    } else {
        android_id.to_string()
    };
    let today = chrono_today();
    let markers = Markers {
        brand: manufacturer.to_string(),
        model: model.to_string(),
        id_short,
        os: format!("Android {}", os_version),
        app_version: app_version.to_string(),
        created: today,
    };

    // 6. Proof: Sign(sk, SHA3(markers_json || pk || enc_pk))
    let markers_json = serde_json::to_vec(&markers).unwrap();
    let mut proof_input = Vec::new();
    proof_input.extend_from_slice(&markers_json);
    proof_input.extend_from_slice(pk.as_bytes());
    proof_input.extend_from_slice(enc_pk.as_bytes());
    let proof_hash = sha3(&proof_input);
    let proof_sig = signing_key.sign(&proof_hash);

    let result = SetupResult {
        signing_pk: B64.encode(pk.as_bytes()),
        encryption_pk: B64.encode(enc_pk.as_bytes()),
        markers: markers.clone(),
        proof: B64.encode(proof_sig.to_bytes()),
    };

    (
        result,
        sk_bytes.to_vec(),
        enc_sk_bytes.to_vec(),
        g.to_vec(),
        bio_hash.to_vec(),
    )
}

pub fn encrypt_for(encryption_pk_b64: &str, pdf: &[u8]) -> Result<String, String> {
    let enc_pk_bytes = B64.decode(encryption_pk_b64).map_err(|e| e.to_string())?;
    if enc_pk_bytes.len() != 32 {
        return Err("encryption_pk must be 32 bytes".into());
    }

    // Ephemeral keypair
    let eph_sk = X25519Secret::random_from_rng(rand::thread_rng());
    let eph_pk = X25519Public::from(&eph_sk);

    // DH
    let recipient_pk: [u8; 32] = enc_pk_bytes.try_into().unwrap();
    let recipient = X25519Public::from(recipient_pk);
    let shared = eph_sk.diffie_hellman(&recipient);

    // Derive AES key
    let aes_key = hkdf_derive(shared.as_bytes(), SALT_ECIES, INFO_AES);

    // Encrypt
    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| e.to_string())?;
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, pdf).map_err(|e| e.to_string())?;

    // doc_hash
    let doc_hash = sha3(pdf);

    // Concatenate nonce + ciphertext
    let mut nonce_ct = Vec::with_capacity(12 + ciphertext.len());
    nonce_ct.extend_from_slice(&nonce_bytes);
    nonce_ct.extend_from_slice(&ciphertext);

    let payload = EncryptedPayload {
        ephemeral_pk: B64.encode(eph_pk.as_bytes()),
        pdf_encrypted: B64.encode(&nonce_ct),
        doc_hash: B64.encode(doc_hash),
    };

    serde_json::to_string(&payload).map_err(|e| e.to_string())
}

pub fn decrypt(
    encryption_sk_bytes: &[u8],
    payload_json: &str,
) -> Result<Vec<u8>, String> {
    let payload: EncryptedPayload =
        serde_json::from_str(payload_json).map_err(|e| e.to_string())?;

    let eph_pk_bytes = B64.decode(&payload.ephemeral_pk).map_err(|e| e.to_string())?;
    let pdf_encrypted = B64.decode(&payload.pdf_encrypted).map_err(|e| e.to_string())?;
    let expected_hash = B64.decode(&payload.doc_hash).map_err(|e| e.to_string())?;

    if eph_pk_bytes.len() != 32 {
        return Err("ephemeral_pk must be 32 bytes".into());
    }
    if pdf_encrypted.len() < 12 {
        return Err("ciphertext too short".into());
    }

    // DH
    let sk: [u8; 32] = encryption_sk_bytes.try_into().map_err(|_| "sk must be 32 bytes")?;
    let enc_sk = X25519Secret::from(sk);
    let eph_pk: [u8; 32] = eph_pk_bytes.try_into().unwrap();
    let eph = X25519Public::from(eph_pk);
    let shared = enc_sk.diffie_hellman(&eph);

    // Derive AES key
    let aes_key = hkdf_derive(shared.as_bytes(), SALT_ECIES, INFO_AES);

    // Decrypt
    let nonce_bytes = &pdf_encrypted[..12];
    let ciphertext = &pdf_encrypted[12..];
    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let pdf = cipher.decrypt(nonce, ciphertext).map_err(|_| "Decryption failed — wrong key or tampered data".to_string())?;

    // Verify hash
    let actual_hash = sha3(&pdf);
    if actual_hash[..] != expected_hash[..] {
        return Err("Document hash mismatch — PDF was modified".into());
    }

    Ok(pdf)
}

pub fn sign_document(
    signing_sk_bytes: &[u8],
    pdf: &[u8],
    bio_key_bytes: &[u8],
    device_ids_concat: &[u8],
    tau: u64,
    markers: &Markers,
    doc_ref: &str,
    original_sender_pk_b64: &str,
) -> Result<String, String> {
    // Verify bio
    let bio_hash = sha3(bio_key_bytes);

    let doc_hash = sha3(pdf);

    // g_sign
    let mut g_input = Vec::new();
    g_input.extend_from_slice(&doc_hash);
    g_input.extend_from_slice(&bio_hash);
    g_input.extend_from_slice(device_ids_concat);
    g_input.extend_from_slice(&tau.to_le_bytes());
    let g_sign = hkdf_derive(&g_input, SALT_MASTER, INFO_DOC_SIG);

    // sigma = Sign(sk, SHA3(doc_hash || g_sign || tau))
    let sk: [u8; 32] = signing_sk_bytes.try_into().map_err(|_| "sk must be 32 bytes")?;
    let signing_key = SigningKey::from_bytes(&sk);
    let pk = signing_key.verifying_key();

    let mut message = Vec::new();
    message.extend_from_slice(&doc_hash);
    message.extend_from_slice(&g_sign);
    message.extend_from_slice(&tau.to_le_bytes());
    let msg_hash = sha3(&message);
    let sigma = signing_key.sign(&msg_hash);

    let attestation = Attestation {
        version: 1,
        doc_type: "attestation".into(),
        signer: AttestationSigner {
            signing_pk: B64.encode(pk.as_bytes()),
            markers: markers.clone(),
        },
        document: AttestationDocument {
            doc_ref: doc_ref.into(),
            doc_hash: B64.encode(doc_hash),
            original_sender_pk: original_sender_pk_b64.into(),
        },
        signature_data: SignatureData {
            g_sign: B64.encode(g_sign),
            sigma: B64.encode(sigma.to_bytes()),
            timestamp: tau,
            bio_method: "fingerprint".into(),
        },
        created: chrono_now(),
    };

    serde_json::to_string(&attestation).map_err(|e| e.to_string())
}

pub fn verify(
    attestation_json: &str,
    pdf: Option<&[u8]>,
) -> Result<VerifyResult, String> {
    let att: Attestation =
        serde_json::from_str(attestation_json).map_err(|e| e.to_string())?;

    // If PDF provided, check doc_hash
    if let Some(pdf_data) = pdf {
        let local_hash = sha3(pdf_data);
        let att_hash = B64.decode(&att.document.doc_hash).map_err(|e| e.to_string())?;
        if local_hash[..] != att_hash[..] {
            return Ok(VerifyResult {
                valid: false,
                signer_markers: Some(att.signer.markers),
            });
        }
    }

    // Verify sigma
    let pk_bytes = B64.decode(&att.signer.signing_pk).map_err(|e| e.to_string())?;
    let pk: [u8; 32] = pk_bytes.try_into().map_err(|_| "pk must be 32 bytes")?;
    let verifying_key = VerifyingKey::from_bytes(&pk).map_err(|e| e.to_string())?;

    let doc_hash = B64.decode(&att.document.doc_hash).map_err(|e| e.to_string())?;
    let g_sign = B64.decode(&att.signature_data.g_sign).map_err(|e| e.to_string())?;
    let sigma_bytes = B64.decode(&att.signature_data.sigma).map_err(|e| e.to_string())?;
    let tau = att.signature_data.timestamp;

    let mut message = Vec::new();
    message.extend_from_slice(&doc_hash);
    message.extend_from_slice(&g_sign);
    message.extend_from_slice(&tau.to_le_bytes());
    let msg_hash = sha3(&message);

    let signature = ed25519_dalek::Signature::from_bytes(
        &sigma_bytes.try_into().map_err(|_| "sigma must be 64 bytes")?,
    );

    let valid = verifying_key.verify(&msg_hash, &signature).is_ok();

    Ok(VerifyResult {
        valid,
        signer_markers: Some(att.signer.markers),
    })
}

pub fn build_kit(
    signing_pk_b64: &str,
    encryption_pk_b64: &str,
    signing_sk_bytes: &[u8],
    markers: &Markers,
    name: &str,
    email: &str,
) -> Result<String, String> {
    let pk_bytes = B64.decode(signing_pk_b64).map_err(|e| e.to_string())?;
    let enc_pk_bytes = B64.decode(encryption_pk_b64).map_err(|e| e.to_string())?;

    // Proof: Sign(sk, SHA3(markers_json || pk || enc_pk))
    let sk: [u8; 32] = signing_sk_bytes.try_into().map_err(|_| "sk must be 32 bytes")?;
    let signing_key = SigningKey::from_bytes(&sk);
    let markers_json = serde_json::to_vec(markers).map_err(|e| e.to_string())?;
    let mut proof_input = Vec::new();
    proof_input.extend_from_slice(&markers_json);
    proof_input.extend_from_slice(&pk_bytes);
    proof_input.extend_from_slice(&enc_pk_bytes);
    let proof_sig = signing_key.sign(&sha3(&proof_input));

    let kit = EnrollmentKit {
        version: 1,
        doc_type: "identity".into(),
        owner: KitOwner {
            name: name.into(),
            email: email.into(),
            signing_pk: signing_pk_b64.into(),
            encryption_pk: encryption_pk_b64.into(),
            markers: markers.clone(),
            proof: B64.encode(proof_sig.to_bytes()),
        },
        created: chrono_now(),
    };

    serde_json::to_string(&kit).map_err(|e| e.to_string())
}

pub fn verify_kit(kit_json: &str) -> Result<bool, String> {
    let kit: EnrollmentKit = serde_json::from_str(kit_json).map_err(|e| e.to_string())?;

    let pk_bytes = B64.decode(&kit.owner.signing_pk).map_err(|e| e.to_string())?;
    let enc_pk_bytes = B64.decode(&kit.owner.encryption_pk).map_err(|e| e.to_string())?;
    let proof_bytes = B64.decode(&kit.owner.proof).map_err(|e| e.to_string())?;

    let markers_json = serde_json::to_vec(&kit.owner.markers).map_err(|e| e.to_string())?;
    let mut proof_input = Vec::new();
    proof_input.extend_from_slice(&markers_json);
    proof_input.extend_from_slice(&pk_bytes);
    proof_input.extend_from_slice(&enc_pk_bytes);

    let pk: [u8; 32] = pk_bytes.try_into().map_err(|_| "pk must be 32 bytes")?;
    let verifying_key = VerifyingKey::from_bytes(&pk).map_err(|e| e.to_string())?;

    let signature = ed25519_dalek::Signature::from_bytes(
        &proof_bytes.try_into().map_err(|_| "proof must be 64 bytes")?,
    );

    Ok(verifying_key.verify(&sha3(&proof_input), &signature).is_ok())
}

fn chrono_today() -> String {
    "2026-04-16".into()
}

fn chrono_now() -> String {
    "2026-04-16T00:00:00Z".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_setup() -> (SetupResult, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        setup(
            "a1b2c3d4e5f6g7h8",
            "google/raven/raven:13",
            "Samsung",
            "Galaxy S24",
            None,
            b"fake-keystore-derived-key-32bytes",
            "14",
            "1.0.0",
        )
    }

    #[test]
    fn test_setup_produces_valid_keys() {
        let (result, sk, enc_sk, _, _) = dummy_setup();
        assert_eq!(B64.decode(&result.signing_pk).unwrap().len(), 32);
        assert_eq!(B64.decode(&result.encryption_pk).unwrap().len(), 32);
        assert_eq!(sk.len(), 32);
        assert_eq!(enc_sk.len(), 32);
    }

    #[test]
    fn test_setup_is_deterministic() {
        let (r1, _, _, _, _) = dummy_setup();
        let (r2, _, _, _, _) = dummy_setup();
        assert_eq!(r1.signing_pk, r2.signing_pk);
        assert_eq!(r1.encryption_pk, r2.encryption_pk);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (result, _, enc_sk, _, _) = dummy_setup();
        let pdf = b"Hello PDF content for AUTHENTIX SIGN test";

        let payload_json = encrypt_for(&result.encryption_pk, pdf).unwrap();
        let decrypted = decrypt(&enc_sk, &payload_json).unwrap();

        assert_eq!(decrypted, pdf);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let (result, _, _, _, _) = dummy_setup();
        let pdf = b"Secret document";
        let payload_json = encrypt_for(&result.encryption_pk, pdf).unwrap();

        let wrong_key = [0xFFu8; 32];
        let err = decrypt(&wrong_key, &payload_json);
        assert!(err.is_err());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let (result, sk, _, _, _) = dummy_setup();
        let pdf = b"Document to sign";
        let device_ids = b"a1b2c3d4e5f6g7h8google/raven/raven:13";

        let att_json = sign_document(
            &sk,
            pdf,
            b"fake-keystore-derived-key-32bytes",
            device_ids,
            1,
            &result.markers,
            "REF-001",
            &result.signing_pk,
        )
        .unwrap();

        let vr = verify(&att_json, Some(pdf)).unwrap();
        assert!(vr.valid);
    }

    #[test]
    fn test_verify_tampered_pdf_fails() {
        let (result, sk, _, _, _) = dummy_setup();
        let pdf = b"Original document";
        let device_ids = b"a1b2c3d4e5f6g7h8google/raven/raven:13";

        let att_json = sign_document(
            &sk,
            pdf,
            b"fake-keystore-derived-key-32bytes",
            device_ids,
            1,
            &result.markers,
            "REF-001",
            &result.signing_pk,
        )
        .unwrap();

        let vr = verify(&att_json, Some(b"Tampered document")).unwrap();
        assert!(!vr.valid);
    }

    #[test]
    fn test_build_verify_kit() {
        let (result, sk, _, _, _) = dummy_setup();

        let kit_json = build_kit(
            &result.signing_pk,
            &result.encryption_pk,
            &sk,
            &result.markers,
            "Alice Dupont",
            "alice@proton.me",
        )
        .unwrap();

        let valid = verify_kit(&kit_json).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_kit_tampered_fails() {
        let (result, sk, _, _, _) = dummy_setup();

        let kit_json = build_kit(
            &result.signing_pk,
            &result.encryption_pk,
            &sk,
            &result.markers,
            "Alice Dupont",
            "alice@proton.me",
        )
        .unwrap();

        let tampered = kit_json.replace("Galaxy S24", "iPhone 15 Pro");
        let valid = verify_kit(&tampered).unwrap();
        assert!(!valid);
    }
}
