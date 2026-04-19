use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Markers {
    pub brand: String,
    pub model: String,
    pub id_short: String,
    pub os: String,
    pub app_version: String,
    pub created: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SetupResult {
    pub signing_pk: String,
    pub encryption_pk: String,
    pub markers: Markers,
    pub proof: String,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub kem_ciphertext: String,
    pub pdf_encrypted: String,
    pub doc_hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct Attestation {
    pub version: u8,
    #[serde(rename = "type")]
    pub doc_type: String,
    pub signer: AttestationSigner,
    pub document: AttestationDocument,
    pub signature_data: SignatureData,
    pub created: String,
}

#[derive(Serialize, Deserialize)]
pub struct AttestationSigner {
    pub signing_pk: String,
    pub markers: Markers,
}

#[derive(Serialize, Deserialize)]
pub struct AttestationDocument {
    #[serde(rename = "ref")]
    pub doc_ref: String,
    pub doc_hash: String,
    pub original_sender_pk: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignatureData {
    pub g_sign: String,
    pub sigma: String,
    pub counter: u64,
    pub bio_method: String,
    /// Phase 2 — TUTE physical/energy monotonic metric, gated behind the
    /// `phiproof-tau` feature in the SDK Rust. None for Phase 1 attestations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tau_tute: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct EnrollmentKit {
    pub version: u8,
    #[serde(rename = "type")]
    pub doc_type: String,
    pub owner: KitOwner,
    pub created: String,
}

#[derive(Serialize, Deserialize)]
pub struct KitOwner {
    pub name: String,
    pub email: String,
    pub signing_pk: String,
    pub encryption_pk: String,
    pub markers: Markers,
    pub proof: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyResult {
    pub valid: bool,
    pub signer_markers: Option<Markers>,
}
