package app.authentixsign

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

object BiometricHelper {

    private const val TAG = "AuthentixBio"
    private const val KEYSTORE_ALIAS = "authentix_bio_key"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    private fun ensureKeyExists() {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(KEYSTORE_ALIAS)) return

        val builder = KeyGenParameterSpec.Builder(
            KEYSTORE_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .setUserAuthenticationRequired(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        }

        builder.setInvalidatedByBiometricEnrollment(true)

        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(builder.build()) }
            .generateKey()

        Log.d(TAG, "KeyStore key created")
    }

    private fun getSecretKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return (ks.getEntry(KEYSTORE_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
    }

    private fun getCipher(): Cipher {
        return Cipher.getInstance(
            "${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_CBC}/${KeyProperties.ENCRYPTION_PADDING_PKCS7}"
        )
    }

    fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        onSuccess: (ByteArray) -> Unit,
        onError: (String) -> Unit,
    ) {
        // Check biometric availability
        val bioManager = BiometricManager.from(activity)
        val canAuth = bioManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
            val reason = when (canAuth) {
                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "Pas de capteur biométrique"
                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "Capteur indisponible"
                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "Aucune empreinte enregistrée dans les paramètres Android"
                else -> "Biométrie non disponible (code $canAuth)"
            }
            Log.e(TAG, "canAuthenticate failed: $reason")
            onError(reason)
            return
        }

        val executor = ContextCompat.getMainExecutor(activity)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                Log.d(TAG, "Auth succeeded, cryptoObject=${result.cryptoObject != null}")
                val cipher = result.cryptoObject?.cipher
                if (cipher != null) {
                    try {
                        val challenge = "AUTHENTIX-BIO-CHALLENGE".toByteArray()
                        val encrypted = cipher.doFinal(challenge)
                        onSuccess(encrypted)
                    } catch (e: Exception) {
                        Log.e(TAG, "doFinal failed", e)
                        onSuccess("AUTHENTIX-BIO-FALLBACK-${System.nanoTime()}".toByteArray())
                    }
                } else {
                    onSuccess("AUTHENTIX-BIO-FALLBACK-${System.nanoTime()}".toByteArray())
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                Log.e(TAG, "Auth error: $errorCode — $errString")
                onError(errString.toString())
            }

            override fun onAuthenticationFailed() {
                Log.w(TAG, "Auth failed (wrong finger), will retry")
            }
        }

        val prompt = BiometricPrompt(activity, executor, callback)

        // Try with CryptoObject first (strongest binding)
        try {
            ensureKeyExists()
            val cipher = getCipher()
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey())
            val cryptoObject = BiometricPrompt.CryptoObject(cipher)

            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                .setNegativeButtonText("Annuler")
                .build()

            Log.d(TAG, "Showing BiometricPrompt with CryptoObject")
            prompt.authenticate(info, cryptoObject)

        } catch (e: Exception) {
            // CryptoObject init failed — fallback to simple biometric auth
            Log.w(TAG, "CryptoObject init failed, falling back to simple auth", e)

            // Delete and recreate the key for next time
            try {
                val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
                ks.deleteEntry(KEYSTORE_ALIAS)
            } catch (_: Exception) {}

            try {
                val info = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(title)
                    .setSubtitle(subtitle)
                    .setNegativeButtonText("Annuler")
                    .build()

                Log.d(TAG, "Showing BiometricPrompt WITHOUT CryptoObject (fallback)")
                prompt.authenticate(info)

            } catch (e2: Exception) {
                Log.e(TAG, "BiometricPrompt.authenticate failed entirely", e2)
                onError("Impossible d'ouvrir le capteur biométrique : ${e2.message}")
            }
        }
    }
}
