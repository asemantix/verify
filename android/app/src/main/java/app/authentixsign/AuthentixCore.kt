package app.authentixsign

object AuthentixCore {
    init {
        System.loadLibrary("authentix_core")
    }

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

    external fun encryptFor(encryptionPkB64: String, pdfBytes: ByteArray): String

    external fun decrypt(encryptionSk: ByteArray, payloadJson: String): String

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

    external fun verify(attestationJson: String, pdfBytes: ByteArray): String

    external fun buildKit(
        signingPkB64: String,
        encryptionPkB64: String,
        signingSk: ByteArray,
        markersJson: String,
        name: String,
        email: String,
    ): String

    external fun verifyKit(kitJson: String): String
}
