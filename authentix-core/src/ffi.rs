use base64::Engine;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::jlong;
use jni::JNIEnv;

use crate::crypto;
use crate::types::Markers;

fn jstring_to_string(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s).map(|s| s.into()).unwrap_or_default()
}

fn jbytes_to_vec(env: &JNIEnv, arr: &JByteArray) -> Vec<u8> {
    env.convert_byte_array(arr).unwrap_or_default()
}

fn return_string(env: &mut JNIEnv, s: &str) -> jni::sys::jstring {
    env.new_string(s)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// JNI: setup(androidId, buildFingerprint, manufacturer, model, keystoreAttestation, bioKeyBytes, osVersion, appVersion) -> JSON
#[no_mangle]
pub extern "system" fn Java_app_authentixsign_AuthentixCore_setup(
    mut env: JNIEnv,
    _class: JClass,
    android_id: JString,
    build_fingerprint: JString,
    manufacturer: JString,
    model: JString,
    keystore_attestation: JByteArray,
    bio_key_bytes: JByteArray,
    os_version: JString,
    app_version: JString,
) -> jni::sys::jstring {
    let aid = jstring_to_string(&mut env, &android_id);
    let bf = jstring_to_string(&mut env, &build_fingerprint);
    let mfr = jstring_to_string(&mut env, &manufacturer);
    let mdl = jstring_to_string(&mut env, &model);
    let att = jbytes_to_vec(&env, &keystore_attestation);
    let bio = jbytes_to_vec(&env, &bio_key_bytes);
    let osv = jstring_to_string(&mut env, &os_version);
    let apv = jstring_to_string(&mut env, &app_version);

    let att_opt = if att.is_empty() { None } else { Some(att.as_slice()) };

    let (result, sk, enc_sk, g, bio_hash) =
        crypto::setup(&aid, &bf, &mfr, &mdl, att_opt, &bio, &osv, &apv);

    // Return everything the Kotlin side needs to store
    let output = serde_json::json!({
        "kit": result,
        "signing_sk": base64::engine::general_purpose::STANDARD.encode(&sk),
        "encryption_sk": base64::engine::general_purpose::STANDARD.encode(&enc_sk),
        "master_seed": base64::engine::general_purpose::STANDARD.encode(&g),
        "bio_hash": base64::engine::general_purpose::STANDARD.encode(&bio_hash),
    });

    return_string(&mut env, &output.to_string())
}

/// JNI: encryptFor(encryptionPkB64, pdfBytes) -> JSON payload
#[no_mangle]
pub extern "system" fn Java_app_authentixsign_AuthentixCore_encryptFor(
    mut env: JNIEnv,
    _class: JClass,
    encryption_pk_b64: JString,
    pdf_bytes: JByteArray,
) -> jni::sys::jstring {
    let pk = jstring_to_string(&mut env, &encryption_pk_b64);
    let pdf = jbytes_to_vec(&env, &pdf_bytes);

    match crypto::encrypt_for(&pk, &pdf) {
        Ok(json) => return_string(&mut env, &json),
        Err(e) => return_string(&mut env, &format!("{{\"error\":\"{}\"}}", e)),
    }
}

/// JNI: decrypt(encryptionSkBytes, payloadJson) -> PDF bytes (base64)
#[no_mangle]
pub extern "system" fn Java_app_authentixsign_AuthentixCore_decrypt(
    mut env: JNIEnv,
    _class: JClass,
    encryption_sk: JByteArray,
    payload_json: JString,
) -> jni::sys::jstring {
    let sk = jbytes_to_vec(&env, &encryption_sk);
    let json = jstring_to_string(&mut env, &payload_json);

    match crypto::decrypt(&sk, &json) {
        Ok(pdf) => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&pdf);
            return_string(&mut env, &b64)
        }
        Err(e) => return_string(&mut env, &format!("ERROR:{}", e)),
    }
}

/// JNI: signDocument(signingSkBytes, pdfBytes, bioKeyBytes, deviceIdsConcat, tau, markersJson, docRef, originalSenderPkB64) -> attestation JSON
#[no_mangle]
pub extern "system" fn Java_app_authentixsign_AuthentixCore_signDocument(
    mut env: JNIEnv,
    _class: JClass,
    signing_sk: JByteArray,
    pdf_bytes: JByteArray,
    bio_key_bytes: JByteArray,
    device_ids_concat: JByteArray,
    tau: jlong,
    markers_json: JString,
    doc_ref: JString,
    original_sender_pk_b64: JString,
) -> jni::sys::jstring {
    let sk = jbytes_to_vec(&env, &signing_sk);
    let pdf = jbytes_to_vec(&env, &pdf_bytes);
    let bio = jbytes_to_vec(&env, &bio_key_bytes);
    let ids = jbytes_to_vec(&env, &device_ids_concat);
    let markers_str = jstring_to_string(&mut env, &markers_json);
    let dref = jstring_to_string(&mut env, &doc_ref);
    let spk = jstring_to_string(&mut env, &original_sender_pk_b64);

    let markers: Markers = match serde_json::from_str(&markers_str) {
        Ok(m) => m,
        Err(e) => return return_string(&mut env, &format!("{{\"error\":\"{}\"}}", e)),
    };

    match crypto::sign_document(&sk, &pdf, &bio, &ids, tau as u64, &markers, &dref, &spk) {
        Ok(json) => return_string(&mut env, &json),
        Err(e) => return_string(&mut env, &format!("{{\"error\":\"{}\"}}", e)),
    }
}

/// JNI: verify(attestationJson, pdfBytes) -> JSON { valid, signer_markers }
#[no_mangle]
pub extern "system" fn Java_app_authentixsign_AuthentixCore_verify(
    mut env: JNIEnv,
    _class: JClass,
    attestation_json: JString,
    pdf_bytes: JByteArray,
) -> jni::sys::jstring {
    let att = jstring_to_string(&mut env, &attestation_json);
    let pdf = jbytes_to_vec(&env, &pdf_bytes);
    let pdf_opt = if pdf.is_empty() { None } else { Some(pdf.as_slice()) };

    match crypto::verify(&att, pdf_opt) {
        Ok(vr) => {
            let json = serde_json::to_string(&vr).unwrap_or_default();
            return_string(&mut env, &json)
        }
        Err(e) => return_string(&mut env, &format!("{{\"error\":\"{}\"}}", e)),
    }
}

/// JNI: buildKit(signingPkB64, encryptionPkB64, signingSkBytes, markersJson, name, email) -> kit JSON
#[no_mangle]
pub extern "system" fn Java_app_authentixsign_AuthentixCore_buildKit(
    mut env: JNIEnv,
    _class: JClass,
    signing_pk_b64: JString,
    encryption_pk_b64: JString,
    signing_sk: JByteArray,
    markers_json: JString,
    name: JString,
    email: JString,
) -> jni::sys::jstring {
    let spk = jstring_to_string(&mut env, &signing_pk_b64);
    let epk = jstring_to_string(&mut env, &encryption_pk_b64);
    let sk = jbytes_to_vec(&env, &signing_sk);
    let markers_str = jstring_to_string(&mut env, &markers_json);
    let n = jstring_to_string(&mut env, &name);
    let e = jstring_to_string(&mut env, &email);

    let markers: Markers = match serde_json::from_str(&markers_str) {
        Ok(m) => m,
        Err(err) => return return_string(&mut env, &format!("{{\"error\":\"{}\"}}", err)),
    };

    match crypto::build_kit(&spk, &epk, &sk, &markers, &n, &e) {
        Ok(json) => return_string(&mut env, &json),
        Err(err) => return_string(&mut env, &format!("{{\"error\":\"{}\"}}", err)),
    }
}

/// JNI: verifyKit(kitJson) -> "true" | "false" | error
#[no_mangle]
pub extern "system" fn Java_app_authentixsign_AuthentixCore_verifyKit(
    mut env: JNIEnv,
    _class: JClass,
    kit_json: JString,
) -> jni::sys::jstring {
    let kit = jstring_to_string(&mut env, &kit_json);

    match crypto::verify_kit(&kit) {
        Ok(valid) => return_string(&mut env, if valid { "true" } else { "false" }),
        Err(e) => return_string(&mut env, &format!("ERROR:{}", e)),
    }
}
