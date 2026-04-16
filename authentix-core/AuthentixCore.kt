package app.authentixsign

/**
 * JNI bridge to the native authentix-core Rust library.
 * All crypto operations live in the compiled .so — this class only exposes the FFI surface.
 *
 * Usage: copy libauthentix_core.so into app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}/
 */
object AuthentixCore {
    init {
        System.loadLibrary("authentix_core")
    }

    /** Generate identity keys from device IDs + biometric key. Returns JSON with kit + secrets. */
    external fun setup(
        androidId: String,
        buildFingerprint: String,
        manufacturer: String,
        model: String,
        keystoreAttestation: ByteArray,
        bioKeyBytes: ByteArray,
        osVersion: String,
        appVersion: String,
    ): String

    /** Encrypt a PDF for a recipient. Returns EncryptedPayload JSON. */
    external fun encryptFor(encryptionPkB64: String, pdfBytes: ByteArray): String

    /** Decrypt a PDF. Returns base64-encoded PDF bytes, or "ERROR:..." on failure. */
    external fun decrypt(encryptionSk: ByteArray, payloadJson: String): String

    /** Sign a document. Returns Attestation JSON. */
    external fun signDocument(
        signingSk: ByteArray,
        pdfBytes: ByteArray,
        bioKeyBytes: ByteArray,
        deviceIdsConcat: ByteArray,
        tau: Long,
        markersJson: String,
        docRef: String,
        originalSenderPkB64: String,
    ): String

    /** Verify an attestation. Returns VerifyResult JSON { valid, signer_markers }. */
    external fun verify(attestationJson: String, pdfBytes: ByteArray): String

    /** Build an enrollment kit (.authentix-id). Returns EnrollmentKit JSON. */
    external fun buildKit(
        signingPkB64: String,
        encryptionPkB64: String,
        signingSk: ByteArray,
        markersJson: String,
        name: String,
        email: String,
    ): String

    /** Verify an enrollment kit. Returns "true" or "false", or "ERROR:..." on failure. */
    external fun verifyKit(kitJson: String): String
}
