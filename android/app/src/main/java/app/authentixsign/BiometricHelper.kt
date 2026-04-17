package app.authentixsign

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Biometric-gated key wrapping via Android Keystore (StrongBox → TEE fallback).
 *
 * AES-256-GCM wrap key is bound to biometrics:
 *   - setUserAuthenticationRequired(true)       → each wrap/unwrap needs a fresh BiometricPrompt
 *   - setInvalidatedByBiometricEnrollment(true) → key destroyed if enrollment changes
 *
 * Blob layout: [version:1][iv:12][ciphertext+tag].
 */
object BiometricHelper {

    private const val TAG = "SesameBio"
    private const val KEYSTORE_ALIAS = "sesame_wrap_key_v1"
    private const val LEGACY_ALIAS = "authentix_bio_key"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val IV_SIZE = 12
    private const val TAG_BITS = 128
    private const val BLOB_VERSION: Byte = 1

    /** Returns null if biometrics are usable, else a French error message. */
    fun checkBiometricAvailable(context: Context): String? {
        val bm = BiometricManager.from(context)
        val r = bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        return when (r) {
            BiometricManager.BIOMETRIC_SUCCESS -> null
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "Aucun capteur biométrique sur ce téléphone"
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "Capteur biométrique indisponible"
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "Aucune empreinte enregistrée — ajoutez-en une dans les paramètres Android"
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "Mise à jour de sécurité Android requise"
            else -> "Biométrie non disponible (code $r)"
        }
    }

    fun keyExists(): Boolean = try {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.containsAlias(KEYSTORE_ALIAS)
    } catch (e: Exception) {
        Log.w(TAG, "keyExists: ${e.message}")
        false
    }

    /** Detects enrollment-invalidation by attempting a cipher init. */
    fun isKeyUsable(): Boolean = try {
        if (!keyExists()) false
        else {
            Cipher.getInstance(TRANSFORMATION).init(Cipher.ENCRYPT_MODE, getSecretKey())
            true
        }
    } catch (_: KeyPermanentlyInvalidatedException) {
        false
    } catch (e: Exception) {
        Log.w(TAG, "isKeyUsable: ${e.message}")
        false
    }

    /** Removes the Keystore entry (and the legacy v0 entry if present). */
    fun destroyKey() {
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (ks.containsAlias(KEYSTORE_ALIAS)) ks.deleteEntry(KEYSTORE_ALIAS)
            if (ks.containsAlias(LEGACY_ALIAS)) ks.deleteEntry(LEGACY_ALIAS)
        } catch (e: Exception) {
            Log.w(TAG, "destroyKey: ${e.message}")
        }
    }

    fun wrapKey(
        activity: FragmentActivity,
        promptTitle: String,
        promptSubtitle: String,
        plaintext: ByteArray,
        onSuccess: (blob: ByteArray) -> Unit,
        onError: (msg: String) -> Unit,
        onInvalidated: () -> Unit,
    ) {
        checkBiometricAvailable(activity)?.let { onError(it); return }
        if (!ensureKeyExists()) { onError("Impossible de créer la clé hardware"); return }

        val cipher = try {
            Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, getSecretKey()) }
        } catch (_: KeyPermanentlyInvalidatedException) {
            Log.w(TAG, "Key invalidated at wrap init")
            onInvalidated(); return
        } catch (e: Exception) {
            onError("Initialisation du chiffrement échouée : ${e.message}"); return
        }

        showPrompt(activity, promptTitle, promptSubtitle, cipher,
            onAuth = { c ->
                try {
                    val ct = c.doFinal(plaintext)
                    val iv = c.iv
                    require(iv.size == IV_SIZE) { "unexpected IV size ${iv.size}" }
                    val blob = ByteArray(1 + IV_SIZE + ct.size)
                    blob[0] = BLOB_VERSION
                    System.arraycopy(iv, 0, blob, 1, IV_SIZE)
                    System.arraycopy(ct, 0, blob, 1 + IV_SIZE, ct.size)
                    onSuccess(blob)
                } catch (e: Exception) {
                    Log.e(TAG, "wrap doFinal failed", e)
                    onError("Chiffrement échoué : ${e.message}")
                }
            },
            onError = onError,
            onInvalidated = onInvalidated,
        )
    }

    fun unwrapKey(
        activity: FragmentActivity,
        promptTitle: String,
        promptSubtitle: String,
        blob: ByteArray,
        onSuccess: (plaintext: ByteArray) -> Unit,
        onError: (msg: String) -> Unit,
        onInvalidated: () -> Unit,
    ) {
        checkBiometricAvailable(activity)?.let { onError(it); return }
        if (!keyExists()) { onError("Clé hardware introuvable"); return }

        if (blob.size < 1 + IV_SIZE + 16 || blob[0] != BLOB_VERSION) {
            onError("Format de blob invalide"); return
        }
        val iv = blob.copyOfRange(1, 1 + IV_SIZE)
        val ct = blob.copyOfRange(1 + IV_SIZE, blob.size)

        val cipher = try {
            Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, getSecretKey(), GCMParameterSpec(TAG_BITS, iv))
            }
        } catch (_: KeyPermanentlyInvalidatedException) {
            Log.w(TAG, "Key invalidated at unwrap init")
            onInvalidated(); return
        } catch (e: Exception) {
            onError("Initialisation du déchiffrement échouée : ${e.message}"); return
        }

        showPrompt(activity, promptTitle, promptSubtitle, cipher,
            onAuth = { c ->
                try {
                    val pt = c.doFinal(ct)
                    onSuccess(pt)
                } catch (e: Exception) {
                    Log.e(TAG, "unwrap doFinal failed", e)
                    onError("Déchiffrement échoué : ${e.message}")
                }
            },
            onError = onError,
            onInvalidated = onInvalidated,
        )
    }

    // ── internals ────────────────────────────────────────────────────────

    private fun showPrompt(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        cipher: Cipher,
        onAuth: (Cipher) -> Unit,
        onError: (String) -> Unit,
        onInvalidated: () -> Unit,
    ) {
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val c = result.cryptoObject?.cipher
                if (c == null) { onError("CryptoObject absent"); return }
                onAuth(c)
            }
            override fun onAuthenticationError(code: Int, msg: CharSequence) {
                Log.w(TAG, "Auth error $code: $msg")
                // USER_CANCELED and NEGATIVE_BUTTON are normal — surface as plain message
                onError(msg.toString())
            }
        }
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText("Annuler")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()
        try {
            BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
                .authenticate(info, BiometricPrompt.CryptoObject(cipher))
        } catch (_: KeyPermanentlyInvalidatedException) {
            onInvalidated()
        } catch (e: Exception) {
            Log.e(TAG, "authenticate threw", e)
            onError("Ouverture du capteur biométrique échouée : ${e.message}")
        }
    }

    private fun getSecretKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return (ks.getEntry(KEYSTORE_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
    }

    /** Creates the key if absent. StrongBox first, silent TEE fallback. */
    private fun ensureKeyExists(): Boolean {
        if (keyExists()) return true
        fun spec(strongBox: Boolean): KeyGenParameterSpec {
            val b = KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                b.setIsStrongBoxBacked(true)
            }
            return b.build()
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                    .apply { init(spec(strongBox = true)) }
                    .generateKey()
                Log.d(TAG, "Key created (StrongBox)")
                return true
            } catch (_: StrongBoxUnavailableException) {
                Log.d(TAG, "StrongBox unavailable, falling back to TEE")
            } catch (e: Exception) {
                Log.w(TAG, "StrongBox attempt failed (${e.javaClass.simpleName}), trying TEE")
            }
        }
        return try {
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                .apply { init(spec(strongBox = false)) }
                .generateKey()
            Log.d(TAG, "Key created (TEE)")
            true
        } catch (e: Exception) {
            Log.e(TAG, "TEE key creation failed", e)
            false
        }
    }
}
