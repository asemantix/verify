//! Generate a deterministic-looking test identity kit for local testing.
//!
//! Usage:
//!     cargo run --example gen_test_kit -- path/to/output.sesame-id [Name]
//!
//! The output is a fully self-certified ML-DSA-65 kit that verify_kit()
//! accepts. It is NOT tied to a real device — the Android fingerprint
//! and android_id fields are made-up identifiers that still produce a
//! valid post-quantum signature over the markers.

use std::fs;
use std::path::Path;

use authentix_core::crypto::{build_kit, setup};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out_path = args.get(1).cloned().unwrap_or_else(|| "alice-test.sesame-id".into());
    let name = args.get(2).cloned().unwrap_or_else(|| "Alice Test".into());

    let android_id = "alice0001test0002alicetest0003id";
    let bio_key = b"ALICE-TEST-BIO-KEY-DETERMINISTIC";

    let (setup_result, signing_sk_bytes, _enc_sk, _master_seed, _bio_hash) = setup(
        android_id,
        "Sesame/alice-test/userdebug",
        "SesameTest",
        "TestPhone 1",
        None,
        bio_key,
        "15",
        "1.0.0",
    );

    let kit_json = build_kit(
        &setup_result.signing_pk,
        &setup_result.encryption_pk,
        &signing_sk_bytes,
        &setup_result.markers,
        &name,
        "",
    )
    .expect("build_kit failed");

    let p = Path::new(&out_path);
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).expect("create parent dir");
        }
    }
    fs::write(p, &kit_json).expect("write kit file");
    println!("Wrote {} bytes → {}", kit_json.len(), p.display());
}
