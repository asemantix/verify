use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hkdf::Hkdf;
use pqcrypto_dilithium::dilithium3::{
    self, DetachedSignature, PublicKey as DilithiumPk, SecretKey as DilithiumSk,
};
use pqcrypto_kyber::kyber768::{self, Ciphertext, PublicKey as KyberPk, SecretKey as KyberSk};
use pqcrypto_traits::kem::{
    Ciphertext as CiphertextTrait, PublicKey as KemPkTrait, SecretKey as KemSkTrait,
    SharedSecret as SharedSecretTrait,
};
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSigTrait, PublicKey as SignPkTrait, SecretKey as SignSkTrait,
};
use sha3::{Digest, Sha3_256};

use crate::types::*;

const SALT_MASTER: &[u8] = b"SESAME-SIGN-v3-PQ";
const SALT_KEM: &[u8] = b"SESAME-KEM-v3";
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

/// Setup: generate ML-DSA-65 + ML-KEM-768 keypairs, build markers and self-certification proof.
/// Returns (SetupResult, signing_sk_bytes, encryption_sk_bytes, master_seed, bio_hash).
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
    // 1. Derive master seed from device IDs (for G_sig computation, not key generation)
    let mut id_material = Vec::new();
    id_material.extend_from_slice(android_id.as_bytes());
    id_material.extend_from_slice(build_fingerprint.as_bytes());
    if let Some(att) = keystore_attestation {
        id_material.extend_from_slice(att);
    }
    let g = hkdf_derive(&id_material, SALT_MASTER, INFO_SEED);

    // 2. bio_hash from KeyStore-backed key bytes
    let bio_hash = sha3(bio_key_bytes);

    // 3. Generate ML-DSA-65 signing keypair (random, NIST FIPS 204)
    let (signing_pk, signing_sk) = dilithium3::keypair();

    // 4. Generate ML-KEM-768 encryption keypair (random, NIST FIPS 203)
    let (enc_pk, enc_sk) = kyber768::keypair();

    // 5. Build markers
    let id_short = if android_id.len() >= 8 {
        format!(
            "{}...{}",
            &android_id[..4],
            &android_id[android_id.len() - 4..]
        )
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

    // 6. Proof: Sign_ML-DSA(sk, SHA3(markers_json || pk || enc_pk))
    let markers_json = serde_json::to_vec(&markers).unwrap();
    let mut proof_input = Vec::new();
    proof_input.extend_from_slice(&markers_json);
    proof_input.extend_from_slice(signing_pk.as_bytes());
    proof_input.extend_from_slice(enc_pk.as_bytes());
    let proof_hash = sha3(&proof_input);
    let proof_sig = dilithium3::detached_sign(&proof_hash, &signing_sk);

    let result = SetupResult {
        signing_pk: B64.encode(signing_pk.as_bytes()),
        encryption_pk: B64.encode(enc_pk.as_bytes()),
        markers,
        proof: B64.encode(proof_sig.as_bytes()),
    };

    // Store signing key as pk(1952) || sk(4032) = 5984 bytes
    // This allows sign_document to recover the pk without changing the JNI interface.
    let mut signing_blob = Vec::with_capacity(1952 + 4032);
    signing_blob.extend_from_slice(signing_pk.as_bytes());
    signing_blob.extend_from_slice(signing_sk.as_bytes());

    (
        result,
        signing_blob,
        enc_sk.as_bytes().to_vec(),
        g.to_vec(),
        bio_hash.to_vec(),
    )
}

/// Encrypt a PDF for a recipient using ML-KEM-768 encapsulation + AES-256-GCM.
pub fn encrypt_for(encryption_pk_b64: &str, pdf: &[u8]) -> Result<String, String> {
    let enc_pk_bytes = B64.decode(encryption_pk_b64).map_err(|e| e.to_string())?;

    let recipient_pk =
        KyberPk::from_bytes(&enc_pk_bytes).map_err(|_| "invalid ML-KEM-768 public key")?;

    // KEM encapsulation: produces shared_secret + ciphertext
    let (shared_secret, kem_ct) = kyber768::encapsulate(&recipient_pk);

    // Derive AES key from shared secret
    let aes_key = hkdf_derive(shared_secret.as_bytes(), SALT_KEM, INFO_AES);

    // Encrypt PDF with AES-256-GCM
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
        kem_ciphertext: B64.encode(kem_ct.as_bytes()),
        pdf_encrypted: B64.encode(&nonce_ct),
        doc_hash: B64.encode(doc_hash),
    };

    serde_json::to_string(&payload).map_err(|e| e.to_string())
}

/// Decrypt a PDF using ML-KEM-768 decapsulation + AES-256-GCM.
pub fn decrypt(encryption_sk_bytes: &[u8], payload_json: &str) -> Result<Vec<u8>, String> {
    let payload: EncryptedPayload =
        serde_json::from_str(payload_json).map_err(|e| e.to_string())?;

    let kem_ct_bytes = B64.decode(&payload.kem_ciphertext).map_err(|e| e.to_string())?;
    let pdf_encrypted = B64.decode(&payload.pdf_encrypted).map_err(|e| e.to_string())?;
    let expected_hash = B64.decode(&payload.doc_hash).map_err(|e| e.to_string())?;

    if pdf_encrypted.len() < 12 {
        return Err("ciphertext too short".into());
    }

    // Reconstruct KEM ciphertext and secret key
    let kem_ct =
        Ciphertext::from_bytes(&kem_ct_bytes).map_err(|_| "invalid ML-KEM-768 ciphertext")?;
    let enc_sk =
        KyberSk::from_bytes(encryption_sk_bytes).map_err(|_| "invalid ML-KEM-768 secret key")?;

    // KEM decapsulation
    let shared_secret = kyber768::decapsulate(&kem_ct, &enc_sk);

    // Derive AES key
    let aes_key = hkdf_derive(shared_secret.as_bytes(), SALT_KEM, INFO_AES);

    // Decrypt
    let nonce_bytes = &pdf_encrypted[..12];
    let ciphertext = &pdf_encrypted[12..];
    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let pdf = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed — wrong key or tampered data".to_string())?;

    // Verify hash
    let actual_hash = sha3(&pdf);
    if actual_hash[..] != expected_hash[..] {
        return Err("Document hash mismatch — PDF was modified".into());
    }

    Ok(pdf)
}

// Implémentation partielle du brevet PhiProof — AION ASEMANTIX
// G = Φ(TAG_SIGN, doc_hash, IDben, I(D), β)
//
// I(D) = clé non exportable Android Keystore / StrongBox (TEE)
//        identifiant matériel intrinsèque au sens du brevet
// β    = biométrie locale — fusionnée, jamais transmise
// TAG  = TAG_SIGN (signature de document)
//
// Manquant Phase 2 :
// τ    = métrique temporelle énergétique (brevet TUTE)
//        garantira la non-rejouabilité par propriété physique monotone
//
// Brevet auto-certification pk : FR2605030
// Sans CA, sans serveur, sans connexion réseau
/// Sign a document with ML-DSA-65. Produces an attestation JSON.
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
    let bio_hash = sha3(bio_key_bytes);
    let doc_hash = sha3(pdf);

    // g_sign: HKDF(doc_hash || bio_hash || device_ids || tau)
    let mut g_input = Vec::new();
    g_input.extend_from_slice(&doc_hash);
    g_input.extend_from_slice(&bio_hash);
    g_input.extend_from_slice(device_ids_concat);
    g_input.extend_from_slice(&tau.to_le_bytes());
    let g_sign = hkdf_derive(&g_input, SALT_MASTER, INFO_DOC_SIG);

    // signing_sk_bytes = pk(1952) || sk(4032) = 5984 bytes
    if signing_sk_bytes.len() != 1952 + 4032 {
        return Err(format!(
            "signing key blob must be 5984 bytes (pk+sk), got {}",
            signing_sk_bytes.len()
        ));
    }
    let pk_bytes = &signing_sk_bytes[..1952];
    let sk_bytes = &signing_sk_bytes[1952..];

    let signing_sk =
        DilithiumSk::from_bytes(sk_bytes).map_err(|_| "invalid ML-DSA-65 secret key")?;

    // sigma = Sign_ML-DSA(sk, SHA3(doc_hash || g_sign || tau))
    let mut message = Vec::new();
    message.extend_from_slice(&doc_hash);
    message.extend_from_slice(&g_sign);
    message.extend_from_slice(&tau.to_le_bytes());
    let msg_hash = sha3(&message);
    let sigma = dilithium3::detached_sign(&msg_hash, &signing_sk);

    let signing_pk_b64 = B64.encode(pk_bytes);

    let attestation = Attestation {
        version: 3,
        doc_type: "attestation".into(),
        signer: AttestationSigner {
            signing_pk: signing_pk_b64,
            markers: markers.clone(),
        },
        document: AttestationDocument {
            doc_ref: doc_ref.into(),
            doc_hash: B64.encode(doc_hash),
            original_sender_pk: original_sender_pk_b64.into(),
        },
        signature_data: SignatureData {
            g_sign: B64.encode(g_sign),
            sigma: B64.encode(sigma.as_bytes()),
            counter: tau,
            bio_method: "fingerprint".into(),
            tau_tute: None,
        },
        created: chrono_now(),
    };

    serde_json::to_string(&attestation).map_err(|e| e.to_string())
}

/// Verify an attestation signature using ML-DSA-65.
pub fn verify(attestation_json: &str, pdf: Option<&[u8]>) -> Result<VerifyResult, String> {
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

    // Verify sigma with ML-DSA-65
    let pk_bytes = B64
        .decode(&att.signer.signing_pk)
        .map_err(|e| e.to_string())?;
    let verifying_key =
        DilithiumPk::from_bytes(&pk_bytes).map_err(|_| "invalid ML-DSA-65 public key")?;

    let doc_hash = B64.decode(&att.document.doc_hash).map_err(|e| e.to_string())?;
    let g_sign = B64.decode(&att.signature_data.g_sign).map_err(|e| e.to_string())?;
    let sigma_bytes = B64
        .decode(&att.signature_data.sigma)
        .map_err(|e| e.to_string())?;
    let tau = att.signature_data.counter;

    let mut message = Vec::new();
    message.extend_from_slice(&doc_hash);
    message.extend_from_slice(&g_sign);
    message.extend_from_slice(&tau.to_le_bytes());
    let msg_hash = sha3(&message);

    let signature = DetachedSignature::from_bytes(&sigma_bytes)
        .map_err(|_| "invalid ML-DSA-65 signature")?;

    let valid =
        dilithium3::verify_detached_signature(&signature, &msg_hash, &verifying_key).is_ok();

    Ok(VerifyResult {
        valid,
        signer_markers: Some(att.signer.markers),
    })
}

// Auto-certification d'une clé publique par preuve de liaison
// au dispositif physique — sans autorité de certification.
// Brevet AION ASEMANTIX FR2605030.
//
// build_kit  : produit {pk, marqueurs, preuve}
//              preuve = Sign(sk, H(marqueurs ‖ pk))
//              le fichier .sesame-id est ce kit
//
// verify_kit : vérifie Verify(pk, H(marqueurs ‖ pk), preuve)
//              sans CA, sans serveur, sans connexion réseau
/// Build an enrollment kit (identity file) with self-certification proof (ML-DSA-65).
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

    // signing_sk_bytes = pk(1952) || sk(4032) — extract sk portion
    let raw_sk = if signing_sk_bytes.len() == 1952 + 4032 {
        &signing_sk_bytes[1952..]
    } else {
        signing_sk_bytes
    };
    let signing_sk =
        DilithiumSk::from_bytes(raw_sk).map_err(|_| "invalid ML-DSA-65 secret key")?;

    // Proof: Sign_ML-DSA(sk, SHA3(markers_json || pk || enc_pk))
    let markers_json = serde_json::to_vec(markers).map_err(|e| e.to_string())?;
    let mut proof_input = Vec::new();
    proof_input.extend_from_slice(&markers_json);
    proof_input.extend_from_slice(&pk_bytes);
    proof_input.extend_from_slice(&enc_pk_bytes);
    let proof_sig = dilithium3::detached_sign(&sha3(&proof_input), &signing_sk);

    let kit = EnrollmentKit {
        version: 3,
        doc_type: "identity".into(),
        owner: KitOwner {
            name: name.into(),
            email: email.into(),
            signing_pk: signing_pk_b64.into(),
            encryption_pk: encryption_pk_b64.into(),
            markers: markers.clone(),
            proof: B64.encode(proof_sig.as_bytes()),
        },
        created: chrono_now(),
    };

    serde_json::to_string(&kit).map_err(|e| e.to_string())
}

/// Verify an enrollment kit's self-certification proof (ML-DSA-65).
/// This is the core of the EPKI patent — no CA, no server.
pub fn verify_kit(kit_json: &str) -> Result<bool, String> {
    let kit: EnrollmentKit = serde_json::from_str(kit_json).map_err(|e| e.to_string())?;

    let pk_bytes = B64
        .decode(&kit.owner.signing_pk)
        .map_err(|e| e.to_string())?;
    let enc_pk_bytes = B64
        .decode(&kit.owner.encryption_pk)
        .map_err(|e| e.to_string())?;
    let proof_bytes = B64.decode(&kit.owner.proof).map_err(|e| e.to_string())?;

    let markers_json = serde_json::to_vec(&kit.owner.markers).map_err(|e| e.to_string())?;
    let mut proof_input = Vec::new();
    proof_input.extend_from_slice(&markers_json);
    proof_input.extend_from_slice(&pk_bytes);
    proof_input.extend_from_slice(&enc_pk_bytes);

    let verifying_key =
        DilithiumPk::from_bytes(&pk_bytes).map_err(|_| "invalid ML-DSA-65 public key")?;
    let signature = DetachedSignature::from_bytes(&proof_bytes)
        .map_err(|_| "invalid ML-DSA-65 proof signature")?;

    Ok(
        dilithium3::verify_detached_signature(&signature, &sha3(&proof_input), &verifying_key)
            .is_ok(),
    )
}

fn chrono_today() -> String {
    "2026-04-17".into()
}

fn chrono_now() -> String {
    "2026-04-17T00:00:00Z".into()
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
        // ML-DSA-65: pk=1952 bytes, sk blob=pk(1952)+sk(4032)=5984 bytes
        assert_eq!(B64.decode(&result.signing_pk).unwrap().len(), 1952);
        // ML-KEM-768: pk=1184 bytes, sk=2400 bytes
        assert_eq!(B64.decode(&result.encryption_pk).unwrap().len(), 1184);
        assert_eq!(sk.len(), 1952 + 4032); // pk || sk blob
        assert_eq!(enc_sk.len(), 2400);
    }

    // ────────────────────────────────────────────────────────────────────
    //  KAT — Known-Answer-Tests for tagged_hash + HKDF-SHA3-256
    //  Shared vectors with the SDK Rust for cross-implementation interop.
    // ────────────────────────────────────────────────────────────────────

    /// Domain-separated hash:
    ///   SHA3-256( tag || 0x00 || LE(len p0) || p0 || LE(len p1) || p1 || ... )
    fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(tag);
        h.update(&[0x00u8]);
        for p in parts {
            h.update(&(p.len() as u64).to_le_bytes());
            h.update(p);
        }
        h.finalize().into()
    }

    fn hex32(bytes: &[u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        for b in bytes.iter() {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    /// SDK-shared KAT set for the cross-implementation tagged_hash +
    /// HKDF-SHA3-256 primitives. Uses the spec-as-written formula:
    ///   SHA3-256( tag || 0x00 || LE(|p_i|) || p_i ... )
    /// Vectors aligned with the SDK Rust on 2026-04-19.
    #[test]
    fn kat_tagged_hash_and_hkdf_sha3_256() {
        const TAG_FP:        &[u8] = b"authentix/v2/fingerprint";
        const TAG_SEED_BIND: &[u8] = b"authentix/v2/seed-bind";
        const TAG_KEYDERIV:  &[u8] = b"authentix/v2/seed-keyderiv";
        const TAG_G_SIGN:    &[u8] = b"authentix/v2/g-sign";

        let ikm  = b"authentix-pq-test-ikm";
        let salt = b"authentix-pq-test-salt";

        let k1 = hex32(&tagged_hash(TAG_FP,        &[b"id-device-001", b"id-session-42"]));
        let k2 = hex32(&tagged_hash(TAG_SEED_BIND, &[b"T-fixed",       b"id-device-001"]));
        let k3 = hex32(&tagged_hash(TAG_G_SIGN,    &[b"pk-bytes-demo"]));
        let k4 = hex32(&tagged_hash(TAG_KEYDERIV,  &[b"pk-bytes-demo"]));
        let k5 = hex32(&hkdf_derive(ikm, salt, b"master"));
        let k6 = hex32(&hkdf_derive(ikm, salt, b"kem"));

        println!("KAT 1 (FP)          = {}", k1);
        println!("KAT 2 (SEED_BIND)   = {}", k2);
        println!("KAT 3 (G_SIGN)      = {}", k3);
        println!("KAT 4 (KEYDERIV)    = {}", k4);
        println!("KAT 5 (HKDF master) = {}", k5);
        println!("KAT 6 (HKDF kem)    = {}", k6);

        assert_eq!(k1, "00136211a380b01d04b993f87170edf0ba1a2ef55063385811b923048a9042af");
        assert_eq!(k2, "e2bde94b1d960b82bb4353a269540c1ee212529b551d2e2409875d4005535f7d");
        assert_eq!(k3, "72c905ff62d787742b69cb1b1abd4699b440bcf3633022d18958ba066f5078fa");
        assert_eq!(k4, "e9d6dc49f4494361d88a75530169694d932e68c461ccc5af1e929bcd0cf562c0");
        assert_eq!(k5, "328925d4af41b43fe228e07c58bd2050f1600381a684ed0a932603eb76defd62");
        assert_eq!(k6, "78e2e085f166f8507912ec08980fd78d50a0bb38fc81806045a989f323df2952");
    }

    // Helper: shorten a base64 string to `<first>…<last>` when longer than
    // `keep` chars — keeps JSON samples readable without losing the shape.
    fn short_b64(s: &str) -> String {
        if s.len() <= 20 { s.to_string() } else { format!("{}…{}", &s[..10], &s[s.len() - 6..]) }
    }

    fn short_markers(m: &Markers) -> Markers {
        Markers {
            brand: m.brand.clone(),
            model: m.model.clone(),
            id_short: m.id_short.clone(),
            os: m.os.clone(),
            app_version: m.app_version.clone(),
            created: m.created.clone(),
        }
    }

    /// Pretty-print a real EnrollmentKit and a real Attestation — shape-accurate
    /// JSON samples for SDK Rust Phase 3 alignment. Real values are truncated
    /// for readability but every field name and its JSON ordering is real.
    #[test]
    fn sample_json_enrollment_kit_and_attestation() {
        // 1) Build a real kit through the code, then truncate base64 for display.
        let (setup_res, sk_blob, _enc_sk, _, _) = dummy_setup();
        let kit_json = build_kit(
            &setup_res.signing_pk,
            &setup_res.encryption_pk,
            &sk_blob,
            &setup_res.markers,
            "Marie Dupont",
            "marie.dupont@example.com",
        ).expect("build_kit");
        let mut kit: EnrollmentKit = serde_json::from_str(&kit_json).unwrap();
        kit.owner.signing_pk    = short_b64(&kit.owner.signing_pk);
        kit.owner.encryption_pk = short_b64(&kit.owner.encryption_pk);
        kit.owner.proof         = short_b64(&kit.owner.proof);
        kit.owner.markers       = short_markers(&kit.owner.markers);

        println!("\n========== EnrollmentKit (.sesame-id) ==========");
        println!("{}", serde_json::to_string_pretty(&kit).unwrap());

        // 2) Build a real Attestation through sign_document, then truncate.
        let pdf = b"pretend PDF bytes";
        let bio = b"fake-keystore-derived-key-32bytes";
        let device_ids = b"ANDROID_ID||Build.FINGERPRINT";
        let tau: u64 = 1_713_000_000;
        let doc_ref = "DOC-1713000000000";
        let att_json = sign_document(
            &sk_blob, pdf, bio, device_ids, tau,
            &setup_res.markers, doc_ref, &setup_res.signing_pk,
        ).expect("sign_document");
        let mut att: Attestation = serde_json::from_str(&att_json).unwrap();
        att.signer.signing_pk              = short_b64(&att.signer.signing_pk);
        att.signer.markers                 = short_markers(&att.signer.markers);
        att.document.doc_hash              = short_b64(&att.document.doc_hash);
        att.document.original_sender_pk    = short_b64(&att.document.original_sender_pk);
        att.signature_data.g_sign          = short_b64(&att.signature_data.g_sign);
        att.signature_data.sigma           = short_b64(&att.signature_data.sigma);

        println!("\n========== Attestation (document signé, v3) ==========");
        println!("{}", serde_json::to_string_pretty(&att).unwrap());
    }

    /// Pins the ML-DSA-65 detached-signature size produced by
    /// pqcrypto-dilithium 0.5 — the FIPS 204 final value is 3309 bytes.
    /// If this ever drifts to 3293 the crate has regressed to Round 3
    /// pre-standard parameters and interop breaks.
    #[test]
    fn test_ml_dsa_65_signature_is_3309_bytes_fips204() {
        let (pk, sk) = dilithium3::keypair();
        let msg = b"test message for ML-DSA-65 size assertion";
        let sig = dilithium3::detached_sign(msg, &sk);
        assert_eq!(
            sig.as_bytes().len(),
            3309,
            "ML-DSA-65 signature must be 3309 bytes (FIPS 204 final), \
             not 3293 (Round 3). Upgrade pqcrypto-dilithium if this fails."
        );
        assert_eq!(pk.as_bytes().len(), 1952, "ML-DSA-65 pk must be 1952 bytes");
    }

    #[test]
    fn test_setup_keys_are_random() {
        // ML-DSA/ML-KEM use random keypair generation (not deterministic from seed).
        // Two calls produce different keys.
        let (r1, _, _, _, _) = dummy_setup();
        let (r2, _, _, _, _) = dummy_setup();
        assert_ne!(r1.signing_pk, r2.signing_pk);
        assert_ne!(r1.encryption_pk, r2.encryption_pk);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (result, _, enc_sk, _, _) = dummy_setup();
        let pdf = b"Hello PDF content for SESAME PQ test";

        let payload_json = encrypt_for(&result.encryption_pk, pdf).unwrap();
        let decrypted = decrypt(&enc_sk, &payload_json).unwrap();

        assert_eq!(decrypted, pdf);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let (result, _, _, _, _) = dummy_setup();
        let pdf = b"Secret document";
        let payload_json = encrypt_for(&result.encryption_pk, pdf).unwrap();

        // Generate a different keypair — use its sk to attempt decryption
        let (_, wrong_enc_sk) = kyber768::keypair();
        let err = decrypt(wrong_enc_sk.as_bytes(), &payload_json);
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
