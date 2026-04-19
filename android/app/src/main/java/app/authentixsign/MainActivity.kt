package app.authentixsign

import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.os.CountDownTimer
import android.provider.Settings
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.FragmentActivity
import java.security.SecureRandom
import java.util.Arrays

class MainActivity : FragmentActivity() {

    private enum class Screen { HOME, RECEIVE, READ, SIGN, SEND_DOC, CONTACTS, SESAME_PROFILE, INVITE, MY_ID }
    private var onQrFullscreen = false
    private var onOnboarding = false
    private var onboardingPager: androidx.viewpager2.widget.ViewPager2? = null
    private var onManifesto = false
    private var manifestoFromMyId = false
    private var manifestoPager: androidx.viewpager2.widget.ViewPager2? = null
    /** Invite flow state: 0 = idle, 1 = SMS fired (waiting for return),
     *  2 = email fired (waiting for return → HOME + toast). Consumed in onResume. */
    private var pendingInviteStep = 0
    private var manifestoPage1Lines: List<View> = emptyList()
    private var manifestoPage2Lines: List<View> = emptyList()
    private var manifestoPage1Animated = false
    private var manifestoPage2Animated = false
    private enum class SetupReason { FIRST_TIME, INVALIDATED, LEGACY_RESET, USER_RESET }
    private var setupReason: SetupReason = SetupReason.FIRST_TIME

    // ── Design tokens (from authentix_design_system.html) ───────────────
    private val BG       = Color.parseColor("#f5f4f0")
    private val FG       = Color.parseColor("#1a1a18")
    private val FG2      = Color.parseColor("#3a3a36")
    private val FG3      = Color.parseColor("#6a6860")
    private val FG4      = Color.parseColor("#aaa89e")
    private val PURPLE   = Color.parseColor("#6655c0")
    private val PURPLE_L = Color.parseColor("#f0eefb")
    private val PURPLE_I = Color.parseColor("#ede9fb")
    private val GOLD     = Color.parseColor("#9a7a28")
    private val GOLD_L   = Color.parseColor("#f5eedc")
    private val GREEN    = Color.parseColor("#2d7a2d")
    private val GREEN_L  = Color.parseColor("#edf7ed")
    private val RED      = Color.parseColor("#b83232")
    private val BORDER   = Color.parseColor("#14000000")
    private val WHITE    = Color.WHITE

    private val SERIF_B: Typeface by lazy {
        androidx.core.content.res.ResourcesCompat.getFont(this, R.font.cormorant_garamond_bold)
            ?: Typeface.create("serif", Typeface.BOLD)
    }
    private val MONO: Typeface by lazy {
        androidx.core.content.res.ResourcesCompat.getFont(this, R.font.jetbrains_mono_regular) ?: Typeface.MONOSPACE
    }
    private val MONO_LIGHT: Typeface by lazy {
        androidx.core.content.res.ResourcesCompat.getFont(this, R.font.jetbrains_mono_light) ?: MONO
    }

    private lateinit var container: FrameLayout
    private var currentScreen = Screen.HOME
    private var isSetupDone = false

    // ── Document flow state ──────────────────────────────────────────────
    private var pendingPayloadJson: String? = null
    private var pendingDocRef: String = ""
    private var pendingDocSubject: String = ""
    private var pendingSenderName: String = ""
    private var pendingSenderPk: String = ""
    private var pendingDocMode: String = "signature"   // "signature" | "readonly"
    private var decryptedPdfBytes: ByteArray? = null
    private var lastAttestationJson: String? = null

    private val MAX_PDF_BYTES = 10L * 1024 * 1024   // 10 MB soft limit

    // ── Send flow state ─────────────────────────────────────────────────
    private var selectedPdfBytes: ByteArray? = null
    private var selectedPdfName: String = ""
    private var selectedRecipient: org.json.JSONObject? = null

    // ── Activity result launchers ───────────────────────────────────────
    private val importKitLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@registerForActivityResult
        try {
            val bytes = contentResolver.openInputStream(uri)?.readBytes() ?: throw Exception("Impossible de lire le fichier")
            val kitJson = String(bytes, Charsets.UTF_8)
            val valid = AuthentixCore.verifyKit(kitJson)
            if (valid == "true") {
                val kit = org.json.JSONObject(kitJson)
                val owner = kit.getJSONObject("owner")
                val name = owner.getString("name")
                val markers = owner.getJSONObject("markers")
                val device = "${markers.getString("brand")} ${markers.getString("model")}"
                val idShort = markers.getString("id_short")
                saveContact(name, owner.getString("signing_pk"), owner.getString("encryption_pk"), markers.toString(), device, idShort)
                Toast.makeText(this, "✅ Sésame ajouté : $name — $device", Toast.LENGTH_LONG).show()
            } else {
                Toast.makeText(this, "❌ Clé Sésame non vérifiée — fichier corrompu ou falsifié", Toast.LENGTH_LONG).show()
            }
            when {
                onOnboarding -> advanceOnboardingToPage(2)
                else -> showScreen(Screen.CONTACTS)
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Erreur import : ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private val receiveSesameLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@registerForActivityResult
        handleIntent(Intent().apply { data = uri; type = "application/x-sesame" })
    }

    private val pickPdfLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@registerForActivityResult
        try {
            val bytes = contentResolver.openInputStream(uri)?.readBytes()
                ?: throw Exception("Impossible de lire le fichier")
            val name = uri.lastPathSegment ?: "document.pdf"
            if (bytes.size > MAX_PDF_BYTES) {
                showOversizePdfDialog(bytes, name)
            } else {
                selectedPdfBytes = bytes
                selectedPdfName = name
                Toast.makeText(this, "PDF sélectionné : ${bytes.size} octets", Toast.LENGTH_SHORT).show()
                showScreen(Screen.SEND_DOC)
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Erreur : ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun showOversizePdfDialog(bytes: ByteArray, name: String) {
        android.app.AlertDialog.Builder(this)
            .setTitle("Fichier volumineux")
            .setMessage(
                "Ce document dépasse 10 MB. Pour l'instant, SÉSAME est optimisé pour les documents jusqu'à 10 MB. " +
                "Les envois de fichiers volumineux arrivent prochainement."
            )
            .setNegativeButton("Choisir un autre fichier") { _, _ ->
                pickPdfLauncher.launch(arrayOf("application/pdf"))
            }
            .setPositiveButton("Envoyer quand même") { _, _ ->
                selectedPdfBytes = bytes
                selectedPdfName = name
                Toast.makeText(this, "PDF sélectionné : ${bytes.size} octets", Toast.LENGTH_SHORT).show()
                showScreen(Screen.SEND_DOC)
            }
            .setCancelable(true)
            .show()
    }

    private val scanQrLauncher = registerForActivityResult(
        com.journeyapps.barcodescanner.ScanContract()
    ) { result ->
        val contents = result.contents ?: return@registerForActivityResult
        try {
            val kitJson = contents
            val valid = AuthentixCore.verifyKit(kitJson)
            if (valid == "true") {
                val kit = org.json.JSONObject(kitJson)
                val owner = kit.getJSONObject("owner")
                val name = owner.getString("name")
                val markers = owner.getJSONObject("markers")
                val device = "${markers.getString("brand")} ${markers.getString("model")}"
                val idShort = markers.getString("id_short")
                saveContact(name, owner.getString("signing_pk"), owner.getString("encryption_pk"), markers.toString(), device, idShort)
                Toast.makeText(this, "✅ Identité vérifiée — $name ($device)", Toast.LENGTH_LONG).show()
            } else {
                Toast.makeText(this, "❌ Clé Sésame non vérifiée — QR corrompu ou falsifié", Toast.LENGTH_LONG).show()
            }
            when {
                onOnboarding -> advanceOnboardingToPage(2)
                else -> showScreen(Screen.CONTACTS)
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Erreur QR : ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun launchQrScanner() {
        val options = com.journeyapps.barcodescanner.ScanOptions().apply {
            setDesiredBarcodeFormats(com.journeyapps.barcodescanner.ScanOptions.QR_CODE)
            setPrompt("Scannez le QR d'identité Sésame")
            setCameraId(0)
            setBeepEnabled(false)
            setOrientationLocked(false)
        }
        scanQrLauncher.launch(options)
    }

    // ── Contact storage ─────────────────────────────────────────────────
    private fun saveContact(name: String, signingPk: String, encryptionPk: String, markersJson: String, device: String, idShort: String) {
        val contacts = loadContacts()
        // Dedupe by signing_pk: update in place and clear obsolete flag.
        for (i in 0 until contacts.length()) {
            val c = contacts.getJSONObject(i)
            if (c.optString("signing_pk") == signingPk) {
                c.put("name", name); c.put("encryption_pk", encryptionPk)
                c.put("markers", markersJson); c.put("device", device); c.put("id_short", idShort)
                c.put("obsolete", false)
                prefs().edit().putString("contacts", contacts.toString()).apply()
                return
            }
        }
        contacts.put(org.json.JSONObject().apply {
            put("name", name); put("signing_pk", signingPk); put("encryption_pk", encryptionPk)
            put("markers", markersJson); put("device", device); put("id_short", idShort)
            put("obsolete", false)
        })
        prefs().edit().putString("contacts", contacts.toString()).apply()
    }

    private fun loadContacts(): org.json.JSONArray {
        val raw = prefs().getString("contacts", "[]") ?: "[]"
        return try { org.json.JSONArray(raw) } catch (_: Exception) { org.json.JSONArray() }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        container = FrameLayout(this).apply {
            setBackgroundColor(BG)
            layoutParams = FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
        }
        setContentView(container)

        // Legacy plaintext-key detection: force reset to hardware-backed flow
        val hasLegacyKeys = prefs().contains("signing_sk") || prefs().contains("encryption_sk") ||
                prefs().contains("master_seed") || prefs().contains("bio_hash")
        val hasWrappedKeys = prefs().contains("signing_sk_blob")

        when {
            hasLegacyKeys -> {
                wipeSesameKeys()
                BiometricHelper.destroyKey()
                markAllContactsObsolete()
                setupReason = SetupReason.LEGACY_RESET
                isSetupDone = false
                showSetupScreen()
            }
            hasWrappedKeys && !BiometricHelper.isKeyUsable() -> {
                wipeSesameKeys()
                BiometricHelper.destroyKey()
                markAllContactsObsolete()
                setupReason = SetupReason.INVALIDATED
                isSetupDone = false
                showSetupScreen()
            }
            else -> {
                isSetupDone = prefs().contains("signing_pk")
                when {
                    !isSetupDone -> showSetupScreen()
                    !prefs().getBoolean("manifeste_shown", false) -> showManifesto(fromMyId = false)
                    !prefs().getBoolean("onboarding_done", false) -> showOnboardingScreen()
                    else -> showScreen(Screen.HOME)
                }
            }
        }
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); handleIntent(intent) }

    private fun handleIntent(intent: Intent?) {
        val uri = intent?.data ?: return
        val path = uri.path ?: uri.toString()

        when {
            path.endsWith(".sesame") || intent.type == "application/x-sesame" -> {
                if (!isSetupDone) {
                    Toast.makeText(this, "Identité non créée — lancez l'app d'abord", Toast.LENGTH_LONG).show()
                    return
                }
                try {
                    val bytes = contentResolver.openInputStream(uri)?.readBytes()
                        ?: throw Exception("Impossible de lire le fichier")
                    val jsonStr = String(bytes, Charsets.UTF_8)
                    val doc = org.json.JSONObject(jsonStr)

                    // Extract payload (the EncryptedPayload that Rust decrypt() expects)
                    val payload = doc.getJSONObject("payload")
                    pendingPayloadJson = payload.toString()

                    // Extract sender info
                    val sender = doc.optJSONObject("sender")
                    pendingSenderName = sender?.optString("name", "Inconnu") ?: "Inconnu"
                    pendingSenderPk = sender?.optString("signing_pk", "") ?: ""

                    // Extract doc ref/subject
                    pendingDocRef = doc.optString("ref", "DOC-${System.currentTimeMillis()}")
                    pendingDocSubject = doc.optString("subject", "Document reçu")

                    // Determine mode — "document_readonly" = no signature expected
                    pendingDocMode = when (doc.optString("type", "document")) {
                        "document_readonly" -> "readonly"
                        else -> "signature"
                    }

                    // Verify recipient matches me
                    val recipient = doc.optJSONObject("recipient")
                    val recipientPk = recipient?.optString("encryption_pk", "") ?: ""
                    val myPk = prefs().getString("encryption_pk", "") ?: ""
                    if (recipientPk.isNotEmpty() && myPk.isNotEmpty() && recipientPk != myPk) {
                        Toast.makeText(this, "Ce document n'est pas pour vous", Toast.LENGTH_LONG).show()
                        return
                    }

                    // Verify sender attestation if present (ML-DSA-65)
                    val attestation = doc.optJSONObject("attestation")
                    if (attestation != null) {
                        val vr = AuthentixCore.verify(attestation.toString(), ByteArray(0))
                        try {
                            val vrJson = org.json.JSONObject(vr)
                            if (vrJson.optBoolean("valid", false)) {
                                pendingSenderName += " ✅"
                            }
                        } catch (_: Exception) {}
                    }

                    showScreen(Screen.RECEIVE)

                } catch (e: Exception) {
                    Toast.makeText(this, "Erreur lecture : ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
            path.endsWith(".sesame-id") -> {
                try {
                    val bytes = contentResolver.openInputStream(uri)?.readBytes()
                        ?: throw Exception("Impossible de lire le fichier")
                    val kitJson = String(bytes, Charsets.UTF_8)
                    val valid = AuthentixCore.verifyKit(kitJson)
                    if (valid == "true") {
                        val kit = org.json.JSONObject(kitJson)
                        val owner = kit.getJSONObject("owner")
                        val name = owner.getString("name")
                        val markers = owner.getJSONObject("markers")
                        val device = "${markers.getString("brand")} ${markers.getString("model")}"
                        val idShort = markers.getString("id_short")
                        saveContact(name, owner.getString("signing_pk"), owner.getString("encryption_pk"), markers.toString(), device, idShort)
                        Toast.makeText(this, "✅ Identité vérifiée — $name ($device) ajouté", Toast.LENGTH_LONG).show()
                    } else {
                        Toast.makeText(this, "❌ Clé Sésame non vérifiée — fichier corrompu ou falsifié", Toast.LENGTH_LONG).show()
                    }
                } catch (e: Exception) {
                    Toast.makeText(this, "Erreur import : ${e.message}", Toast.LENGTH_LONG).show()
                }
                when {
                onOnboarding -> advanceOnboardingToPage(2)
                else -> showScreen(Screen.CONTACTS)
            }
            }
        }
    }

    private fun prefs() = getSharedPreferences("authentix", MODE_PRIVATE)

    // ── Identity lifecycle helpers ──────────────────────────────────────

    private fun wipeSesameKeys() {
        prefs().edit().apply {
            remove("signing_pk"); remove("encryption_pk"); remove("markers")
            remove("signing_sk"); remove("encryption_sk")   // legacy plaintext
            remove("master_seed"); remove("bio_hash")       // legacy artifacts
            remove("signing_sk_blob"); remove("encryption_sk_blob")
            remove("signed_kit_json")
            remove("id_created_at")
            remove("transport_mode"); remove("onboarding_done")  // legacy: transport now per-action
        }.apply()
    }

    private fun markAllContactsObsolete() {
        val contacts = loadContacts()
        var changed = false
        for (i in 0 until contacts.length()) {
            val c = contacts.getJSONObject(i)
            if (!c.optBoolean("obsolete", false)) {
                c.put("obsolete", true); changed = true
            }
        }
        if (changed) prefs().edit().putString("contacts", contacts.toString()).apply()
    }

    private fun handleKeyInvalidated() {
        wipeSesameKeys()
        BiometricHelper.destroyKey()
        markAllContactsObsolete()
        setupReason = SetupReason.INVALIDATED
        isSetupDone = false
        showSetupScreen()
    }

    private fun notifyAllContacts() {
        val kitJson = prefs().getString("signed_kit_json", "") ?: ""
        if (kitJson.isEmpty()) {
            Toast.makeText(this, "Kit indisponible", Toast.LENGTH_SHORT).show()
            return
        }
        try {
            val file = java.io.File(cacheDir, "mon-identite.sesame-id")
            file.writeText(kitJson)
            val uri = androidx.core.content.FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "application/x-sesame"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "J'ai une nouvelle identité Sésame — mettez à jour ma clé")
                putExtra(Intent.EXTRA_TEXT, "Mon identité Sésame a changé. Ouvrez ce fichier pour mettre à jour ma clé automatiquement.")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(intent, "Notifier mes Sésames"))
        } catch (e: Exception) {
            Toast.makeText(this, "Erreur : ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    // ════════════════════════════════════════════════════════════════════
    //  SETUP — Premier lancement (thème or / Device)
    // ════════════════════════════════════════════════════════════════════

    private fun showSetupScreen() {
        container.removeAllViews()
        val root = screenRoot()
        root.addView(accentBar(GOLD))

        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(32), dp(24), dp(24))
            layoutParams = lp()
        }

        when (setupReason) {
            SetupReason.INVALIDATED -> {
                body.addView(eyebrow("Identité réinitialisée"))
                body.addView(titleSerif("Nouvelle\nempreinte détectée", GOLD))
                body.addView(sub("Votre identité Sésame a été réinitialisée. Une nouvelle empreinte a été détectée sur ce téléphone. Par sécurité, votre ancienne clé a été détruite."))
                body.addView(spacer(12))
                body.addView(guideText("Posez votre doigt pour créer une nouvelle identité."))
            }
            SetupReason.LEGACY_RESET -> {
                body.addView(eyebrow("Mise à jour de sécurité"))
                body.addView(titleSerif("Identité à\nrecréer", GOLD))
                body.addView(sub("Votre clé est maintenant stockée dans le TEE matériel de votre téléphone, protégée par votre empreinte. L'ancien format de test a été supprimé."))
                body.addView(spacer(12))
                body.addView(guideText("Posez votre doigt pour générer vos nouvelles clés."))
            }
            SetupReason.USER_RESET -> {
                body.addView(eyebrow("Identité réinitialisée"))
                body.addView(titleSerif("Créez une\nnouvelle identité", GOLD))
                body.addView(sub("Votre ancienne clé a été supprimée à votre demande. Posez votre doigt pour en créer une nouvelle."))
            }
            SetupReason.FIRST_TIME -> {
                body.addView(eyebrow("Bienvenue"))
                body.addView(titleSerif("Créez votre\nidentité", GOLD))
                body.addView(sub("Posez votre doigt pour créer votre identité numérique. Elle est liée à CE téléphone et à VOTRE empreinte. Elle ne quitte jamais votre appareil."))
            }
        }
        body.addView(spacer(24))

        val status = sub(""); status.gravity = Gravity.CENTER
        body.addView(status)
        body.addView(spacer(14))

        body.addView(bioZoneFull(GOLD_L, goldBorder(), GOLD, "Confirmer la création", false) {
            status.text = "Génération des clés…"; status.setTextColor(FG3)
            doSetup(status)
        })
        body.addView(spacer(10))
        body.addView(sub("Identité liée à ce téléphone et à vos empreintes actuelles").apply {
            gravity = Gravity.CENTER; setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f); setTextColor(FG4)
        })

        root.addView(body)
        root.addView(dots(1, 3, GOLD))
        container.addView(scroll(root))
    }

    private fun doSetup(status: TextView) {
        // Entropy for Rust setup (hashed into derivation, not a bio proof — bio binding is in Keystore wrap).
        val entropy = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val signingSkB64: String
        val encryptionSkB64: String
        val signingPk: String
        val encryptionPk: String
        val markersJson: String
        try {
            val aid = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID) ?: "unknown"
            val r = AuthentixCore.setup(aid, Build.FINGERPRINT, Build.MANUFACTURER, Build.MODEL, ByteArray(0), entropy, Build.VERSION.RELEASE, "1.0.0")
            val j = org.json.JSONObject(r); val kit = j.getJSONObject("kit")
            signingPk = kit.getString("signing_pk")
            encryptionPk = kit.getString("encryption_pk")
            markersJson = kit.getJSONObject("markers").toString()
            signingSkB64 = j.getString("signing_sk")
            encryptionSkB64 = j.getString("encryption_sk")
        } catch (e: Exception) {
            Arrays.fill(entropy, 0)
            status.text = "Erreur génération : ${e.message}"; status.setTextColor(RED)
            return
        }
        Arrays.fill(entropy, 0)

        // Build the signed kit NOW while the SK is in memory — cached in prefs so "Mon identité" never needs a bio prompt.
        val signingSk = android.util.Base64.decode(signingSkB64, android.util.Base64.DEFAULT)
        val signedKitJson: String = try {
            AuthentixCore.buildKit(signingPk, encryptionPk, signingSk, markersJson,
                Build.MANUFACTURER + " " + Build.MODEL, "")
        } catch (e: Exception) {
            Arrays.fill(signingSk, 0)
            status.text = "Erreur kit : ${e.message}"; status.setTextColor(RED)
            return
        }

        // Combined SK payload for wrapping: {"sign_sk": b64, "enc_sk": b64}
        val combined = org.json.JSONObject().apply {
            put("sign_sk", signingSkB64)
            put("enc_sk", encryptionSkB64)
        }.toString().toByteArray(Charsets.UTF_8)

        status.text = "Scellement dans le TEE…"; status.setTextColor(FG3)

        BiometricHelper.wrapKey(this,
            promptTitle = "Sceller votre identité",
            promptSubtitle = "Posez votre doigt pour protéger vos clés",
            plaintext = combined,
            onSuccess = { blob ->
                Arrays.fill(combined, 0)
                Arrays.fill(signingSk, 0)
                prefs().edit().apply {
                    putString("signing_pk", signingPk)
                    putString("encryption_pk", encryptionPk)
                    putString("markers", markersJson)
                    putString("signing_sk_blob", android.util.Base64.encodeToString(blob, android.util.Base64.NO_WRAP))
                    putString("signed_kit_json", signedKitJson)
                    putLong("id_created_at", System.currentTimeMillis())
                }.apply()
                isSetupDone = true
                status.text = "Identité créée ✓"; status.setTextColor(GREEN)
                val reasonForSuccess = setupReason
                setupReason = SetupReason.FIRST_TIME
                container.postDelayed({
                    when {
                        reasonForSuccess != SetupReason.FIRST_TIME -> showPostSetupSuccess()
                        !prefs().getBoolean("manifeste_shown", false) -> showManifesto(fromMyId = false)
                        !prefs().getBoolean("onboarding_done", false) -> showOnboardingScreen()
                        else -> showScreen(Screen.HOME)
                    }
                }, 900)
            },
            onError = { msg ->
                Arrays.fill(combined, 0); Arrays.fill(signingSk, 0)
                status.text = "Erreur : $msg"; status.setTextColor(RED)
            },
            onInvalidated = {
                // Extremely unlikely at this point (we just created the key), but handle defensively.
                Arrays.fill(combined, 0); Arrays.fill(signingSk, 0)
                status.text = "Clé invalidée — réessayez"; status.setTextColor(RED)
                handleKeyInvalidated()
            },
        )
    }

    private fun showPostSetupSuccess() {
        currentScreen = Screen.HOME
        container.removeAllViews()
        val root = screenRoot()
        root.addView(accentBar(GOLD))
        root.addView(topBar("Sésame", GOLD, badge("Nouvelle identité", GREEN_L, GREEN)))

        val body = bodyPad()
        body.addView(spacer(16))
        body.addView(eyebrow("Identité prête"))
        body.addView(titleSerif("Votre nouvelle\nidentité est prête", GOLD))
        body.addView(sub("Vos Sésames doivent mettre à jour votre clé Sésame pour pouvoir vous envoyer des documents."))
        body.addView(spacer(12))
        body.addView(guideText("Le bouton ci-dessous ouvre votre application mail avec votre nouvelle clé en pièce jointe. Choisissez vos Sésames dans le carnet d'adresses de votre mail."))
        body.addView(spacer(14))

        body.addView(cta("Notifier tous mes Sésames", GOLD) { notifyAllContacts() })
        body.addView(spacer(8))
        body.addView(ctaOutline("Plus tard") { showScreen(Screen.HOME) })

        root.addView(body)
        container.addView(scroll(root))
    }

    // ════════════════════════════════════════════════════════════════════
    //  ÉCRAN TRANSPORT — affiché à chaque Envoyer et chaque Recevoir
    // ════════════════════════════════════════════════════════════════════

    // ════════════════════════════════════════════════════════════════════
    //  MANIFESTO — 2-page swipeable, framed, staggered text fade-in
    //  Shown once before onboarding (flag manifeste_shown) and on-demand
    //  from Mon identité via the "Notre engagement" link.
    // ════════════════════════════════════════════════════════════════════

    private fun showManifesto(fromMyId: Boolean) {
        onManifesto = true
        onOnboarding = false
        onQrFullscreen = false
        manifestoFromMyId = fromMyId
        manifestoPage1Animated = false
        manifestoPage2Animated = false
        container.removeAllViews()

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(BG)
            layoutParams = FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
        }

        val pager = androidx.viewpager2.widget.ViewPager2(this).apply {
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f)
            adapter = ManifestoAdapter()
        }
        manifestoPager = pager
        root.addView(pager)

        val dotsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            setPadding(dp(24), dp(10), dp(24), dp(24))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }
        val dots = Array(2) {
            View(this).apply {
                layoutParams = LinearLayout.LayoutParams(dp(8), dp(8)).apply { setMargins(dp(6), 0, dp(6), 0) }
            }
        }
        fun paintDots(active: Int) {
            for (i in dots.indices) {
                dots[i].background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(PURPLE) }
                dots[i].alpha = if (i == active) 1f else 0.3f
            }
        }
        dots.forEach { dotsRow.addView(it) }
        paintDots(0)
        root.addView(dotsRow)

        pager.registerOnPageChangeCallback(object : androidx.viewpager2.widget.ViewPager2.OnPageChangeCallback() {
            override fun onPageSelected(position: Int) {
                paintDots(position)
                when (position) {
                    0 -> if (!manifestoPage1Animated) {
                        manifestoPage1Animated = true
                        animateManifestoLines(manifestoPage1Lines)
                    }
                    1 -> if (!manifestoPage2Animated) {
                        manifestoPage2Animated = true
                        animateManifestoLines(manifestoPage2Lines)
                    }
                }
            }
        })

        container.addView(root)
        // Kick off page-1 animation after layout settles.
        pager.post {
            if (!manifestoPage1Animated) {
                manifestoPage1Animated = true
                animateManifestoLines(manifestoPage1Lines)
            }
        }
    }

    private fun animateManifestoLines(lines: List<View>) {
        val handler = android.os.Handler(android.os.Looper.getMainLooper())
        val stagger = 800L
        val duration = 500L
        lines.forEachIndexed { i, v ->
            handler.postDelayed({
                v.animate().alpha(1f).setDuration(duration).start()
            }, stagger * i)
        }
    }

    private fun completeManifesto() {
        prefs().edit().putBoolean("manifeste_shown", true).apply()
        val fromMyId = manifestoFromMyId
        onManifesto = false
        manifestoPager = null
        manifestoPage1Lines = emptyList()
        manifestoPage2Lines = emptyList()
        if (fromMyId) {
            showScreen(Screen.MY_ID)
        } else when {
            !prefs().getBoolean("onboarding_done", false) -> showOnboardingScreen()
            else -> showScreen(Screen.HOME)
        }
    }

    private inner class ManifestoAdapter : androidx.recyclerview.widget.RecyclerView.Adapter<ManifestoAdapter.VH>() {
        inner class VH(v: View) : androidx.recyclerview.widget.RecyclerView.ViewHolder(v)
        override fun getItemCount() = 2
        override fun getItemViewType(position: Int) = position
        override fun onCreateViewHolder(parent: android.view.ViewGroup, viewType: Int): VH {
            val v = buildManifestoPage(viewType).apply {
                layoutParams = androidx.recyclerview.widget.RecyclerView.LayoutParams(MATCH_PARENT, MATCH_PARENT)
            }
            return VH(v)
        }
        override fun onBindViewHolder(holder: VH, position: Int) {}
    }

    /** Build one manifesto page with the framed-card decor + staggered text lines. */
    private fun buildManifestoPage(index: Int): View {
        val isDark = (index == 0)
        val cardColor = if (isDark) Color.parseColor("#1a1820") else Color.parseColor("#f5f4f0")
        val textColor = if (isDark) Color.parseColor("#d4d2cc") else Color.parseColor("#6a6860")

        val scroll = ScrollView(this).apply {
            setBackgroundColor(BG)
            layoutParams = FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
            isVerticalFadingEdgeEnabled = false
        }

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(20), dp(20), dp(20))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }

        val frame = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(32), dp(32), dp(32), dp(32))
            background = GradientDrawable().apply {
                setColor(cardColor)
                setStroke(dp(1), Color.argb(77, 0x66, 0x55, 0xc0))   // PURPLE 30%
                cornerRadius = dp(16).toFloat()
            }
            elevation = dp(4).toFloat()
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }

        // Icon + separator (decor — always visible)
        frame.addView(android.widget.ImageView(this).apply {
            setImageResource(R.mipmap.ic_launcher)
            layoutParams = LinearLayout.LayoutParams(dp(32), dp(32)).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                bottomMargin = dp(14)
            }
        })
        frame.addView(View(this).apply {
            setBackgroundColor(Color.argb(51, 0x66, 0x55, 0xc0))  // PURPLE 20%
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 1).apply { bottomMargin = dp(18) }
        })

        val lines = mutableListOf<View>()
        if (index == 0) buildManifestoPage1Content(frame, lines, textColor)
        else buildManifestoPage2Content(frame, lines)

        // All lines start hidden; animated by onPageSelected.
        lines.forEach { it.alpha = 0f }
        if (index == 0) manifestoPage1Lines = lines else manifestoPage2Lines = lines

        container.addView(frame)
        scroll.addView(container)
        return scroll
    }

    private fun buildManifestoPage1Content(frame: LinearLayout, lines: MutableList<View>, textColor: Int) {
        // Title — Cormorant italic 16sp #6655c0 at 0.7 opacity
        val title = TextView(this).apply {
            text = "Contrairement aux autres acteurs du marché —"
            typeface = Typeface.create(SERIF_B, Typeface.ITALIC)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            setTextColor(Color.argb(179, 0x66, 0x55, 0xc0))
            gravity = Gravity.CENTER
            setLineSpacing(0f, 1.25f)
            layoutParams = lp().apply { bottomMargin = dp(6) }
        }
        frame.addView(title); lines.add(title)

        val competitors = TextView(this).apply {
            text = "DocuSign · Adobe Sign · HelloSign · Yousign · et leurs pairs"
            typeface = Typeface.create(MONO, Typeface.ITALIC)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
            setTextColor(Color.argb(128, 0xaa, 0xa8, 0x9e))
            gravity = Gravity.CENTER
            setLineSpacing(0f, 1.3f)
            layoutParams = lp().apply { bottomMargin = dp(14) }
        }
        frame.addView(competitors); lines.add(competitors)

        // Divider under the title
        frame.addView(View(this).apply {
            setBackgroundColor(Color.argb(38, 0x66, 0x55, 0xc0))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 1).apply { bottomMargin = dp(18) }
        })

        val problemLines = listOf(
            "une adresse email.",
            "Un lien cliquable.",
            "Des documents qui voyagent en clair.",
            "Stockés sur des serveurs",
            "que vous ne contrôlez pas.",
            "Des signatures qui ne vous appartiennent plus.",
            "Piratables. Récoltables.",
            "",
            "Un code peut être volé.",
            "Un mot de passe peut être partagé.",
            "Un lien peut être cliqué par n'importe qui.",
            "",
            "Rien ne prouve que c'est vous.",
        )
        // Body — Mono 12sp #d4d2cc at 0.75 opacity, line-height 2.0
        val bodyColor = Color.argb(191, 0xd4, 0xd2, 0xcc)
        for (text in problemLines) {
            val tv = TextView(this).apply {
                this.text = text
                typeface = MONO
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                setTextColor(bodyColor)
                gravity = Gravity.CENTER
                setLineSpacing(0f, 2.0f)
                layoutParams = lp().apply { topMargin = dp(2); bottomMargin = dp(2) }
            }
            frame.addView(tv); lines.add(tv)
        }

        frame.addView(View(this).apply {
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, dp(18))
        })

        val punch = TextView(this).apply {
            text = "Harvest Now, Decrypt Later."
            typeface = Typeface.create(SERIF_B, Typeface.ITALIC)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
            setTextColor(Color.parseColor("#9a3820"))
            gravity = Gravity.CENTER
            setLineSpacing(0f, 1.15f)
            layoutParams = lp().apply { topMargin = dp(12) }
        }
        frame.addView(punch); lines.add(punch)

        // Subtle swipe-hint gradient at the very bottom of the dark card — transparent on
        // the left, a faint purple on the right, suggesting "swipe right for more".
        frame.addView(View(this).apply {
            background = GradientDrawable(
                GradientDrawable.Orientation.LEFT_RIGHT,
                intArrayOf(Color.TRANSPARENT, Color.argb(77, 0x66, 0x55, 0xc0)),
            )
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, dp(3)).apply { topMargin = dp(22) }
        })
        // Small mono cue under the gradient — white at 0.4 opacity.
        val swipeCue = TextView(this).apply {
            text = "glissez →"
            typeface = MONO
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
            setTextColor(Color.argb(102, 0xf5, 0xf4, 0xf0))
            gravity = Gravity.END
            setPadding(0, dp(4), dp(2), 0)
            layoutParams = lp()
        }
        frame.addView(swipeCue); lines.add(swipeCue)
    }

    private fun buildManifestoPage2Content(frame: LinearLayout, lines: MutableList<View>) {
        // Header — company mark, Cormorant 14sp #6655c0 at 0.6 opacity (discreet)
        val brandMark = TextView(this).apply {
            text = "AION ASEMANTIX"
            typeface = SERIF_B
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            setTextColor(Color.argb(153, 0x66, 0x55, 0xc0))
            gravity = Gravity.CENTER
            letterSpacing = 0.08f
            layoutParams = lp().apply { topMargin = dp(2); bottomMargin = dp(2) }
        }
        frame.addView(brandMark); lines.add(brandMark)

        val brandSub = TextView(this).apply {
            text = "Lyon, France · 2026"
            typeface = MONO
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
            setTextColor(Color.argb(128, 0xaa, 0xa8, 0x9e))
            gravity = Gravity.CENTER
            layoutParams = lp().apply { topMargin = dp(2); bottomMargin = dp(18) }
        }
        frame.addView(brandSub); lines.add(brandSub)

        // Body — Mono 12sp #6a6860 with 2.0 line-spacing (same treatment for opening claim,
        // body paragraphs and closing fine details — unified "corps" style).
        val bodyColor = Color.parseColor("#6a6860")
        fun addBody(text: String) {
            val tv = TextView(this).apply {
                this.text = text
                typeface = MONO
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                setTextColor(bodyColor)
                gravity = Gravity.CENTER
                setLineSpacing(0f, 2.0f)
                layoutParams = lp().apply { topMargin = dp(1); bottomMargin = dp(1) }
            }
            frame.addView(tv); lines.add(tv)
        }

        val bodyHead = listOf(
            "Sésame instaure un nouveau protocole mondial",
            "d'échanges et de signatures de documents",
            "entre parties identifiées.",
            "",
            "Sans tiers de confiance.",
            "Sans serveur.",
            "",
            "L'expéditeur et le signataire",
            "sont irréversiblement liés au document.",
            "Mathématiquement authentifiés.",
            "",
            "Chaque signature produit un certificat.",
            "Valeur juridique probatoire.",
            "Conforme eIDAS 2.",
            "La preuve est là. Pour toujours.",
            "",
            "Vos documents ne transitent nulle part.",
            "Vos documents chiffrés sont indistinguables",
            "du bruit aléatoire.",
            "Aucun opérateur réseau, aucun data center",
            "ne peut en établir l'existence.",
            "",
        )
        for (t in bodyHead) addBody(t)

        // Accent — "C'est l'asémanticité." in Cormorant italic 16sp PURPLE
        val asemanticityAccent = TextView(this).apply {
            text = "C'est l'asémanticité."
            typeface = Typeface.create(SERIF_B, Typeface.ITALIC)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            setTextColor(PURPLE)
            gravity = Gravity.CENTER
            setLineSpacing(0f, 1.3f)
            layoutParams = lp().apply { topMargin = dp(6); bottomMargin = dp(2) }
        }
        frame.addView(asemanticityAccent); lines.add(asemanticityAccent)

        val bodyTail = listOf(
            "Le principe fondateur d'AION ASEMANTIX.",
            "",
            "Ils n'existent sur aucun serveur.",
            "On ne peut pas récolter",
            "ce qui n'existe pas.",
        )
        for (t in bodyTail) addBody(t)

        frame.addView(View(this).apply {
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, dp(14))
        })

        val punch = TextView(this).apply {
            text = "Harvest Now, Decrypt Never."
            typeface = Typeface.create(SERIF_B, Typeface.ITALIC)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
            setTextColor(PURPLE)
            gravity = Gravity.CENTER
            setLineSpacing(0f, 1.15f)
            layoutParams = lp().apply { topMargin = dp(10); bottomMargin = dp(14) }
        }
        frame.addView(punch); lines.add(punch)

        val tailLines = listOf(
            "Résistant aux ordinateurs quantiques.",
            "ML-DSA-65 · ML-KEM-768",
            "NIST FIPS 203 & 204.",
            "",
            "Vos documents sont à vous.",
            "Pour toujours.",
        )
        for (text in tailLines) {
            val tv = TextView(this).apply {
                this.text = text
                typeface = MONO
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                setTextColor(bodyColor)
                gravity = Gravity.CENTER
                setLineSpacing(0f, 2.0f)
                layoutParams = lp().apply { topMargin = dp(1); bottomMargin = dp(1) }
            }
            frame.addView(tv); lines.add(tv)
        }

        val enterBtn = TextView(this).apply {
            text = "[ Entrer ]"
            typeface = SERIF_B
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 20f)
            setTextColor(PURPLE)
            gravity = Gravity.CENTER
            setPadding(dp(16), dp(14), dp(16), dp(14))
            isClickable = true; isFocusable = true
            setOnClickListener { completeManifesto() }
            layoutParams = lp().apply { topMargin = dp(20) }
        }
        frame.addView(enterBtn); lines.add(enterBtn)

        val patentMark = TextView(this).apply {
            text = "Innovation brevetée 2026"
            typeface = MONO
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f)
            setTextColor(Color.argb(128, 0xaa, 0xa8, 0x9e))
            gravity = Gravity.CENTER
            letterSpacing = 0.06f
            layoutParams = lp().apply { topMargin = dp(14); bottomMargin = dp(6) }
        }
        frame.addView(patentMark); lines.add(patentMark)
    }

    // ════════════════════════════════════════════════════════════════════
    //  ONBOARDING — 3-page swipeable ViewPager (shown once after setup)
    // ════════════════════════════════════════════════════════════════════

    private fun showOnboardingScreen() {
        onOnboarding = true
        onQrFullscreen = false
        container.removeAllViews()

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(BG)
            layoutParams = FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
        }
        root.addView(accentBar(PURPLE))

        val pager = androidx.viewpager2.widget.ViewPager2(this).apply {
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f)
            adapter = OnboardingAdapter()
            orientation = androidx.viewpager2.widget.ViewPager2.ORIENTATION_HORIZONTAL
            isUserInputEnabled = true   // horizontal swipes between pages are the only navigation
            offscreenPageLimit = 1
        }
        onboardingPager = pager
        root.addView(pager)

        // Dots indicator — 3 circles, active one is solid purple, others 30% opacity.
        val dotsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            setPadding(dp(24), dp(18), dp(24), dp(12))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }
        val dots = Array(3) {
            View(this).apply {
                layoutParams = LinearLayout.LayoutParams(dp(8), dp(8)).apply { setMargins(dp(6), 0, dp(6), 0) }
            }
        }
        fun paintDots(active: Int) {
            for (i in dots.indices) {
                dots[i].background = GradientDrawable().apply {
                    shape = GradientDrawable.OVAL
                    setColor(PURPLE)
                }
                dots[i].alpha = if (i == active) 1f else 0.3f
            }
        }
        dots.forEach { dotsRow.addView(it) }
        paintDots(0)
        root.addView(dotsRow)

        // Skip link — discreet, on every page (always visible under the dots).
        root.addView(TextView(this).apply {
            text = "Passer l'onboarding"
            typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f); setTextColor(FG4)
            gravity = Gravity.CENTER
            setPadding(dp(12), dp(6), dp(12), dp(18))
            isClickable = true; isFocusable = true
            setOnClickListener { completeOnboarding() }
        })

        pager.registerOnPageChangeCallback(object : androidx.viewpager2.widget.ViewPager2.OnPageChangeCallback() {
            override fun onPageSelected(position: Int) { paintDots(position) }
        })

        container.addView(root)
    }

    private fun completeOnboarding() {
        prefs().edit().putBoolean("onboarding_done", true).apply()
        onOnboarding = false
        onboardingPager = null
        showScreen(Screen.HOME)
    }

    private fun advanceOnboardingToPage(target: Int) {
        onboardingPager?.currentItem = target
    }

    /** RecyclerView adapter for the 3 onboarding pages. Uses viewType = position
     *  so each page reuses the same ViewHolder that was built for its index. */
    private inner class OnboardingAdapter : androidx.recyclerview.widget.RecyclerView.Adapter<OnboardingAdapter.VH>() {
        inner class VH(v: View) : androidx.recyclerview.widget.RecyclerView.ViewHolder(v)
        override fun getItemCount() = 1
        override fun getItemViewType(position: Int) = position
        override fun onCreateViewHolder(parent: android.view.ViewGroup, viewType: Int): VH {
            val v = buildOnboardingPage(viewType).apply {
                layoutParams = androidx.recyclerview.widget.RecyclerView.LayoutParams(MATCH_PARENT, MATCH_PARENT)
            }
            return VH(v)
        }
        override fun onBindViewHolder(holder: VH, position: Int) {}
    }

    /** Single-page onboarding — invite the first Sésame. SMS + email are both fired by
     *  startInviteFlow(), and finishInviteFlow() takes the user straight to HOME. */
    private fun buildOnboardingPage(index: Int): View {
        val scroll = ScrollView(this).apply {
            setBackgroundColor(BG)
            layoutParams = FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
        }
        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(28), dp(40), dp(28), dp(40))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
        }
        body.addView(titleSerif("Invitez votre\npremier Sésame.", PURPLE))
        body.addView(onboardingMonoSub("SMS et email, en une seule fois."))
        body.addView(spacer(24))
        body.addView(ctaTall("Inviter un Sésame", PURPLE) { startInviteFlow() })
        scroll.addView(body)
        return scroll
    }

    private fun onboardingMonoSub(text: String) = TextView(this).apply {
        this.text = text
        typeface = MONO
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
        setTextColor(FG3)
        layoutParams = lp().apply { topMargin = dp(4) }
    }

    /** Full-width 52dp-tall purple primary CTA used on Home, Invite, Send, etc. */
    private fun ctaTall(label: String, bgColor: Int, onClick: () -> Unit) = Button(this).apply {
        text = label.uppercase(); typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f); setTextColor(WHITE)
        letterSpacing = 0.1f; isAllCaps = false; stateListAnimator = null; elevation = 0f
        setPadding(dp(12), 0, dp(12), 0)
        setBackgroundColor(bgColor)
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, dp(52))
        setOnClickListener { onClick() }
    }

    // ── User-initiated identity reset (called from Mon identité danger zone) ──
    private fun confirmUserResetIdentity() {
        android.app.AlertDialog.Builder(this)
            .setTitle("⚠️ Attention")
            .setMessage(
                "Réinitialiser votre identité supprimera définitivement votre clé actuelle.\n\n" +
                "Vos Sésames devront réenregistrer votre nouvelle identité pour pouvoir vous envoyer des documents.\n\n" +
                "Les documents déjà reçus resteront accessibles."
            )
            .setNegativeButton("Annuler", null)
            .setPositiveButton("Confirmer") { _, _ ->
                wipeSesameKeys()
                BiometricHelper.destroyKey()
                markAllContactsObsolete()
                setupReason = SetupReason.USER_RESET
                isSetupDone = false
                showSetupScreen()
            }
            .show()
    }

    // ── QR fullscreen modal ──────────────────────────────────────────────
    private fun showQrFullscreen(kitJson: String) {
        val bmp = generateQr(kitJson) ?: run {
            Toast.makeText(this, "Erreur QR", Toast.LENGTH_SHORT).show(); return
        }
        onQrFullscreen = true
        container.removeAllViews()
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setBackgroundColor(Color.WHITE)
            setPadding(dp(24), dp(24), dp(24), dp(24))
            layoutParams = FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
            isClickable = true
            setOnClickListener {
                // Restore brightness and return to Mon identité.
                window?.attributes = window?.attributes?.apply { screenBrightness = -1f }
                showScreen(Screen.MY_ID)
            }
        }
        layout.addView(android.widget.ImageView(this).apply {
            setImageBitmap(bmp)
            scaleType = android.widget.ImageView.ScaleType.FIT_CENTER
            val size = (resources.displayMetrics.widthPixels * 0.85f).toInt()
            layoutParams = LinearLayout.LayoutParams(size, size)
        })
        layout.addView(TextView(this).apply {
            text = "Faites scanner ce QR par votre Sésame"
            typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f); setTextColor(FG3)
            gravity = Gravity.CENTER
            layoutParams = lp().apply { topMargin = dp(20) }
        })
        layout.addView(TextView(this).apply {
            text = "(Touchez l'écran pour fermer)"
            typeface = MONO_LIGHT; setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f); setTextColor(FG4)
            gravity = Gravity.CENTER
            layoutParams = lp().apply { topMargin = dp(8) }
        })
        window?.attributes = window?.attributes?.apply { screenBrightness = 1f }
        container.addView(layout)
    }

    // ════════════════════════════════════════════════════════════════════
    //  NAVIGATION
    // ════════════════════════════════════════════════════════════════════

    private fun showScreen(s: Screen) {
        currentScreen = s
        onQrFullscreen = false
        onOnboarding = false
        onboardingPager = null
        onManifesto = false
        manifestoPager = null
        manifestoPage1Lines = emptyList()
        manifestoPage2Lines = emptyList()
        container.removeAllViews()
        // HOME is a fixed-layout dashboard (no scroll) so bottom settings can anchor.
        if (s == Screen.HOME) {
            container.addView(buildHome().apply {
                layoutParams = FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
            })
            return
        }
        container.addView(scroll(when (s) {
            Screen.RECEIVE         -> buildReceive()
            Screen.READ            -> buildRead()
            Screen.SIGN            -> buildSign()
            Screen.SEND_DOC        -> buildSendDoc()
            Screen.CONTACTS        -> buildContacts()
            Screen.SESAME_PROFILE  -> buildSesameProfile()
            Screen.INVITE          -> buildInvite()
            Screen.MY_ID           -> buildMyId()
            Screen.HOME            -> buildHome() // unreachable; exhaustiveness only
        }))
    }

    // ════════════════════════════════════════════════════════════════════
    //  1. HOME — Accueil / Scanner QR
    // ════════════════════════════════════════════════════════════════════

    private fun buildHome(): LinearLayout {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(BG)
            layoutParams = FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
        }
        root.addView(accentBar(PURPLE))
        root.addView(topBar("Sésame", PURPLE, iconButton("🆔") { showScreen(Screen.MY_ID) }))

        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(28), dp(36), dp(28), dp(36))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f)
        }

        body.addView(spacer(16))
        body.addView(TextView(this).apply {
            text = "SÉSAME"
            typeface = SERIF_B
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 48f)
            setTextColor(PURPLE)
            gravity = Gravity.CENTER
            layoutParams = lp()
        })
        body.addView(TextView(this).apply {
            text = "Ouvre-toi !"
            typeface = Typeface.create(SERIF_B, Typeface.ITALIC)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
            setTextColor(FG3)
            gravity = Gravity.CENTER
            layoutParams = lp().apply { topMargin = dp(4) }
        })

        // Flex spacer pushes CTAs down toward the middle/lower half.
        body.addView(View(this).apply {
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f)
        })

        val contactCount = loadContacts().length()
        val inviteCount = prefs().getInt("invite_count", 0)
        if (contactCount > 0) {
            body.addView(ctaTall("Mes Sésames ($contactCount)", PURPLE) {
                showScreen(Screen.CONTACTS)
            })
            body.addView(spacer(12))
        }
        // Primary invite CTA only before the first successful invite — afterwards, a
        // discreet link at the bottom covers "+ Inviter un autre Sésame".
        if (inviteCount == 0) {
            body.addView(ctaTall("Inviter un Sésame", PURPLE) { startInviteFlow() })
        }

        body.addView(View(this).apply {
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 0, 0.6f)
        })

        if (inviteCount >= 1) {
            body.addView(TextView(this).apply {
                text = "+ Inviter un autre Sésame"
                typeface = MONO
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
                setTextColor(Color.parseColor("#aaa89e"))
                gravity = Gravity.CENTER
                setPadding(dp(12), dp(8), dp(12), dp(8))
                isClickable = true; isFocusable = true
                setOnClickListener { startInviteFlow() }
                layoutParams = lp().apply { bottomMargin = dp(6) }
            })
        }

        body.addView(TextView(this).apply {
            text = "Vos documents. Vos Sésames. Personne d'autre."
            typeface = MONO
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            setTextColor(FG4)
            gravity = Gravity.CENTER
            layoutParams = lp()
        })

        root.addView(body)
        return root
    }

    /** Small tappable icon rendered in the topBar right-slot. */
    private fun iconButton(emoji: String, onClick: () -> Unit) = TextView(this).apply {
        text = emoji
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f)
        setPadding(dp(10), dp(6), dp(10), dp(6))
        isClickable = true; isFocusable = true
        setOnClickListener { onClick() }
    }

    /** Non-interactive CTA styled like `cta` but grayed with a trailing label. */
    private fun disabledCta(label: String, pendingLabel: String) = Button(this).apply {
        text = "${label.uppercase()}   ·   ${pendingLabel.uppercase()}"
        typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f); setTextColor(FG3)
        letterSpacing = 0.1f; isAllCaps = false; stateListAnimator = null; elevation = 0f
        setPadding(dp(12), dp(12), dp(12), dp(12))
        setBackgroundColor(Color.parseColor("#d8d6cf"))
        alpha = 0.6f
        isEnabled = false
        layoutParams = lp()
    }

    // ════════════════════════════════════════════════════════════════════
    //  2. RECEIVE — Biométrie réception (ton doux)
    // ════════════════════════════════════════════════════════════════════

    private fun buildReceive(): LinearLayout {
        val root = screenRoot()
        root.addView(accentBar(PURPLE))
        root.addView(topBar("Sésame", PURPLE, stepLabel("Étape 1/3")))

        val body = bodyPad()
        body.addView(backLink { pendingPayloadJson = null; decryptedPdfBytes = null; showScreen(Screen.HOME) })
        body.addView(eyebrow("Document reçu"))
        body.addView(titleSerif("Confirmez\nla réception", PURPLE))
        body.addView(sub("Un document chiffré vous a été envoyé. Seul votre appareil peut l'ouvrir."))
        body.addView(guideText("Posez votre empreinte ci-dessous pour prouver que c'est bien vous et déchiffrer le document en toute sécurité."))
        body.addView(spacer(10))

        // Sender info card
        val infoCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(12), dp(12), dp(12), dp(12))
            background = GradientDrawable().apply { setColor(PURPLE_L); setStroke(dp(1), purpleBorder()); cornerRadius = dp(4).toFloat() }
            layoutParams = lp().apply { bottomMargin = dp(14) }
        }
        infoCard.addView(certRow("Expéditeur", pendingSenderName, PURPLE))
        infoCard.addView(certRow("Objet", pendingDocSubject, PURPLE))
        infoCard.addView(certRow("Référence", pendingDocRef, PURPLE))
        body.addView(infoCard)

        val status = sub(""); status.gravity = Gravity.CENTER
        body.addView(status)

        body.addView(bioZoneFull(PURPLE_L, purpleBorder(), PURPLE, "Déchiffrer le document", false) {
            status.text = "Authentification…"; status.setTextColor(FG3)
            val blobB64 = prefs().getString("signing_sk_blob", "") ?: ""
            val blob = android.util.Base64.decode(blobB64, android.util.Base64.DEFAULT)
            BiometricHelper.unwrapKey(this, "Déchiffrer le document", "Confirmez votre identité", blob,
                onSuccess = { combined ->
                    status.text = "Déchiffrement en cours…"; status.setTextColor(FG3)
                    var encSk: ByteArray? = null
                    try {
                        val pair = org.json.JSONObject(String(combined, Charsets.UTF_8))
                        encSk = android.util.Base64.decode(pair.getString("enc_sk"), android.util.Base64.DEFAULT)
                        val result = AuthentixCore.decrypt(encSk, pendingPayloadJson!!)
                        if (result.startsWith("ERROR:")) {
                            status.text = result.removePrefix("ERROR:"); status.setTextColor(RED)
                        } else {
                            decryptedPdfBytes = android.util.Base64.decode(result, android.util.Base64.DEFAULT)
                            status.text = "Déchiffré ✓ (${decryptedPdfBytes!!.size} octets)"; status.setTextColor(GREEN)
                            container.postDelayed({ showScreen(Screen.READ) }, 800)
                        }
                    } catch (e: Exception) {
                        status.text = "Erreur : ${e.message}"; status.setTextColor(RED)
                    } finally {
                        encSk?.let { Arrays.fill(it, 0) }
                        Arrays.fill(combined, 0)
                    }
                },
                onError = { msg -> status.text = "Erreur : $msg"; status.setTextColor(RED) },
                onInvalidated = { handleKeyInvalidated() })
        })
        body.addView(spacer(8))
        body.addView(ctaOutline("Annuler") { pendingPayloadJson = null; showScreen(Screen.HOME) })

        root.addView(body)
        root.addView(dots(2, 5, PURPLE))
        return root
    }

    // ════════════════════════════════════════════════════════════════════
    //  3. READ — Lecture obligatoire (timer + scroll)
    // ════════════════════════════════════════════════════════════════════

    private fun buildRead(): LinearLayout {
        if (pendingDocMode == "readonly") return buildReadOnly()
        val root = screenRoot()
        root.addView(accentBar(PURPLE))
        root.addView(topBar("Sésame", PURPLE, stepLabel("Étape 2/3")))

        val body = bodyPad()
        body.addView(backLink { decryptedPdfBytes = null; pendingPayloadJson = null; showScreen(Screen.HOME) })
        val pdf = decryptedPdfBytes
        val pageCount = pdf?.let { countPdfPages(it) } ?: 1
        val timerSeconds = when {
            pageCount <= 1 -> 10
            pageCount <= 5 -> 20
            else -> 40
        }
        val needScroll = pageCount > 5

        body.addView(eyebrow("Lecture obligatoire"))
        body.addView(titleSerif("Lisez le\ndocument", PURPLE))
        val gateExplainer = when {
            needScroll -> "Document de $pageCount pages. Le bouton s'activera après ${timerSeconds}s OU dès que vous aurez défilé jusqu'en bas."
            else -> "Document de $pageCount page(s). Le bouton s'activera après ${timerSeconds}s de lecture."
        }
        body.addView(guideText(gateExplainer))
        body.addView(spacer(10))

        if (pdf != null) {
            val hashHex = sha3Hex(pdf)
            val infoCard = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL; setPadding(dp(12), dp(12), dp(12), dp(12))
                background = GradientDrawable().apply { setColor(GREEN_L); setStroke(dp(1), Color.argb(46, 45, 122, 45)); cornerRadius = dp(4).toFloat() }
                layoutParams = lp().apply { bottomMargin = dp(10) }
            }
            infoCard.addView(certRow("État", "Déchiffré ✓", GREEN))
            infoCard.addView(certRow("Pages", pageCount.toString(), GREEN))
            infoCard.addView(certRow("Taille", "${pdf.size} octets", GREEN))
            infoCard.addView(certRow("H(doc)", "${hashHex.take(8)}…${hashHex.takeLast(4)}", GREEN))
            infoCard.addView(certRow("Référence", pendingDocRef, GREEN))
            body.addView(infoCard)

            val pdfBitmap = renderPdfFirstPage(pdf)
            if (pdfBitmap != null) {
                body.addView(android.widget.ImageView(this).apply {
                    setImageBitmap(pdfBitmap)
                    scaleType = android.widget.ImageView.ScaleType.FIT_CENTER
                    adjustViewBounds = true
                    setPadding(dp(2), dp(2), dp(2), dp(2))
                    background = card_bg()
                    layoutParams = lp().apply { bottomMargin = dp(14) }
                })
            } else {
                body.addView(docPreview(10))
            }
        } else {
            body.addView(docPreview(10))
        }
        body.addView(spacer(6))

        val timerRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            layoutParams = lp().apply { bottomMargin = dp(14) }
        }
        val timerTxt = timerLabel("0:%02d".format(timerSeconds))
        val timerElapsed = timerLabel("0:00")
        val timerBarBg = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, dp(3), 1f).apply { setMargins(dp(10), 0, dp(10), 0) }
            background = GradientDrawable().apply { setColor(Color.argb(38, 102, 85, 192)); cornerRadius = dp(2).toFloat() }
        }
        timerRow.addView(timerElapsed); timerRow.addView(timerBarBg); timerRow.addView(timerTxt)
        body.addView(timerRow)

        val hint = sub(
            if (needScroll) "Faites défiler jusqu'en bas pour activer la signature"
            else "Lecture obligatoire — le bouton s'active dans ${timerSeconds}s"
        ).apply { gravity = Gravity.CENTER; setTextColor(FG4) }
        body.addView(hint)
        body.addView(spacer(14))

        val signBtn = cta("Signer et renvoyer", PURPLE) { showScreen(Screen.SIGN) }
        signBtn.alpha = 0.4f; signBtn.isEnabled = false
        body.addView(signBtn)

        // Dual-gate state: [timerDone, scrollSatisfied]. For 1-5 pages, scroll is auto-satisfied.
        val gate = booleanArrayOf(false, !needScroll)
        fun maybeUnlock() {
            if (gate[0] && gate[1]) {
                signBtn.alpha = 1f; signBtn.isEnabled = true
                hint.text = "Signature disponible"
            }
        }

        object : CountDownTimer(timerSeconds * 1000L, 1000) {
            var elapsed = 0
            override fun onTick(ms: Long) {
                elapsed++
                timerElapsed.text = "0:%02d".format(elapsed)
                if (!gate[0]) signBtn.alpha = 0.4f + (elapsed.toFloat() / timerSeconds) * 0.4f
            }
            override fun onFinish() {
                timerElapsed.text = "0:%02d".format(timerSeconds)
                gate[0] = true; maybeUnlock()
            }
        }.start()

        if (needScroll) {
            body.post {
                var p: android.view.ViewParent? = body.parent
                while (p != null && p !is ScrollView) p = p.parent
                (p as? ScrollView)?.setOnScrollChangeListener { v, _, sy, _, _ ->
                    val ch = (v as ScrollView).getChildAt(0) ?: return@setOnScrollChangeListener
                    if (ch.bottom - (sy + v.height) <= dp(12)) {
                        gate[1] = true; maybeUnlock()
                    }
                }
            }
        }

        root.addView(body)
        root.addView(dots(3, 5, PURPLE))
        return root
    }

    /** Read-only receive flow — "Envoyer simplement" documents. No timer, no signature. */
    private fun buildReadOnly(): LinearLayout {
        val root = screenRoot()
        root.addView(accentBar(GREEN))
        root.addView(topBar("Sésame", GREEN, stepLabel("Lecture seule")))

        val body = bodyPad()
        body.addView(backLink { decryptedPdfBytes = null; pendingPayloadJson = null; showScreen(Screen.HOME) })
        body.addView(eyebrow("Document reçu"))
        body.addView(titleSerif("Lisez le\ndocument", GREEN))
        body.addView(guideText("Votre Sésame vous a envoyé ce document en lecture seule. Aucune signature n'est attendue."))
        body.addView(spacer(10))

        val pdf = decryptedPdfBytes
        if (pdf != null) {
            val hashHex = sha3Hex(pdf)
            val infoCard = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL; setPadding(dp(12), dp(12), dp(12), dp(12))
                background = GradientDrawable().apply { setColor(GREEN_L); setStroke(dp(1), Color.argb(46, 45, 122, 45)); cornerRadius = dp(4).toFloat() }
                layoutParams = lp().apply { bottomMargin = dp(10) }
            }
            infoCard.addView(certRow("État", "Déchiffré ✓", GREEN))
            infoCard.addView(certRow("Expéditeur", pendingSenderName, GREEN))
            infoCard.addView(certRow("Objet", pendingDocSubject, GREEN))
            infoCard.addView(certRow("Taille", "${pdf.size} octets", GREEN))
            infoCard.addView(certRow("H(doc)", "${hashHex.take(8)}…${hashHex.takeLast(4)}", GREEN))
            infoCard.addView(certRow("Référence", pendingDocRef, GREEN))
            body.addView(infoCard)

            val pdfBitmap = renderPdfFirstPage(pdf)
            if (pdfBitmap != null) {
                body.addView(android.widget.ImageView(this).apply {
                    setImageBitmap(pdfBitmap)
                    scaleType = android.widget.ImageView.ScaleType.FIT_CENTER
                    adjustViewBounds = true
                    setPadding(dp(2), dp(2), dp(2), dp(2))
                    background = card_bg()
                    layoutParams = lp().apply { bottomMargin = dp(14) }
                })
            } else {
                body.addView(docPreview(10))
            }
        } else {
            body.addView(docPreview(10))
        }
        body.addView(spacer(10))

        body.addView(ctaTall("Fermer", GREEN) {
            decryptedPdfBytes = null; pendingPayloadJson = null
            showScreen(Screen.HOME)
        })

        root.addView(body)
        return root
    }

    private fun countPdfPages(pdfBytes: ByteArray): Int {
        if (Build.VERSION.SDK_INT < 21) return 1
        return try {
            val tmp = java.io.File.createTempFile("count_", ".pdf", cacheDir)
            tmp.writeBytes(pdfBytes)
            val fd = android.os.ParcelFileDescriptor.open(tmp, android.os.ParcelFileDescriptor.MODE_READ_ONLY)
            val renderer = android.graphics.pdf.PdfRenderer(fd)
            val n = renderer.pageCount
            renderer.close(); fd.close(); tmp.delete()
            n.coerceAtLeast(1)
        } catch (e: Exception) { 1 }
    }

    // ════════════════════════════════════════════════════════════════════
    //  4. SIGN — Biométrie signature (ton intense)
    // ════════════════════════════════════════════════════════════════════

    private fun buildSign(): LinearLayout {
        val root = screenRoot()
        root.addView(accentBar(PURPLE))
        root.addView(topBar("Sésame", PURPLE, stepLabel("Étape 3/3")))

        val body = bodyPad()
        body.addView(backLink { showScreen(Screen.READ) })
        body.addView(eyebrow("Signature définitive"))
        body.addView(titleSerif("Signez\nmaintenant", PURPLE))
        body.addView(sub("Dernière étape. Votre empreinte scellera définitivement le document."))
        body.addView(guideText("En posant votre doigt, vous confirmez avoir lu le document et acceptez de le signer. Cette action est irréversible — votre signature sera liée à ce document de façon permanente. Aucune donnée ne quitte votre téléphone."))
        body.addView(spacer(14))

        val status = sub(""); status.gravity = Gravity.CENTER
        body.addView(status)

        body.addView(bioZoneFull(PURPLE_I, purpleBorderIntense(), PURPLE, "Maintenir l'empreinte", true) {
            status.text = "Authentification…"; status.setTextColor(FG3)
            val blobB64 = prefs().getString("signing_sk_blob", "") ?: ""
            val blob = android.util.Base64.decode(blobB64, android.util.Base64.DEFAULT)
            BiometricHelper.unwrapKey(this, "Signature définitive", "Maintenez votre empreinte", blob,
                onSuccess = { combined ->
                    status.text = "Signature en cours…"; status.setTextColor(FG3)
                    var sk: ByteArray? = null
                    val bio = ByteArray(32).also { SecureRandom().nextBytes(it) }
                    try {
                        val pdf = decryptedPdfBytes ?: throw Exception("PDF non déchiffré")
                        val pair = org.json.JSONObject(String(combined, Charsets.UTF_8))
                        sk = android.util.Base64.decode(pair.getString("sign_sk"), android.util.Base64.DEFAULT)
                        val markersJson = prefs().getString("markers", "{}") ?: "{}"
                        val aid = android.provider.Settings.Secure.getString(contentResolver, android.provider.Settings.Secure.ANDROID_ID) ?: ""
                        val deviceIds = (aid + Build.FINGERPRINT).toByteArray()
                        val tau = MonotonicCounter.next(this)
                        val senderPk = if (pendingSenderPk.isNotEmpty()) pendingSenderPk else prefs().getString("signing_pk", "") ?: ""

                        val attJson = AuthentixCore.signDocument(
                            sk, pdf, bio, deviceIds, tau,
                            markersJson, pendingDocRef, senderPk
                        )

                        if (attJson.contains("\"error\"")) {
                            status.text = "Erreur signature : $attJson"; status.setTextColor(RED)
                        } else {
                            lastAttestationJson = attJson
                            status.text = "Signé ✓ (τ=$tau)"; status.setTextColor(GREEN)
                            container.postDelayed({ showSuccess() }, 800)
                        }
                    } catch (e: Exception) {
                        status.text = "Erreur : ${e.message}"; status.setTextColor(RED)
                    } finally {
                        sk?.let { Arrays.fill(it, 0) }
                        Arrays.fill(bio, 0)
                        Arrays.fill(combined, 0)
                    }
                },
                onError = { msg -> status.text = "Erreur : $msg"; status.setTextColor(RED) },
                onInvalidated = { handleKeyInvalidated() })
        })
        body.addView(spacer(10))

        // Hash formula
        body.addView(TextView(this).apply {
            text = "G_sig = SHA3-256( TAG ‖ H(doc) ‖ H(IDs) ‖ H(bio) ‖ τ )"
            typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 8f); setTextColor(FG4)
            setLineSpacing(0f, 1.5f)
            layoutParams = lp().apply { bottomMargin = dp(12) }
        })
        body.addView(ctaOutline("Refuser de signer") {
            decryptedPdfBytes = null; pendingPayloadJson = null
            showScreen(Screen.HOME)
        })

        root.addView(body)
        root.addView(dots(4, 5, PURPLE))
        return root
    }

    // ════════════════════════════════════════════════════════════════════
    //  5. SUCCESS — Certificat signé
    // ════════════════════════════════════════════════════════════════════

    private fun showSuccess() {
        currentScreen = Screen.HOME
        container.removeAllViews()
        val root = screenRoot()
        root.addView(accentBar(PURPLE))
        root.addView(topBar("Sésame", PURPLE, badge("Signé", GREEN_L, GREEN)))

        val body = bodyPad()
        body.addView(spacer(16))

        // Check circle
        body.addView(View(this).apply {
            layoutParams = LinearLayout.LayoutParams(dp(36), dp(36)).apply { gravity = Gravity.CENTER_HORIZONTAL; bottomMargin = dp(8) }
            background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setStroke(dp(2), GREEN); setColor(Color.TRANSPARENT) }
        })
        body.addView(TextView(this).apply {
            text = "Document signé"; typeface = SERIF_B; setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f); setTextColor(GREEN); gravity = Gravity.CENTER
            layoutParams = lp()
        })
        body.addView(TextView(this).apply {
            text = "Calcul local · aucun serveur · hors ligne"; typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f); setTextColor(FG4); gravity = Gravity.CENTER
            layoutParams = lp().apply { topMargin = dp(4); bottomMargin = dp(16) }
        })

        // Parse attestation for display
        val tau = MonotonicCounter.peek(this)
        var docHash = "—"
        var sigmaShort = "—"
        var certSize = "—"
        val att = lastAttestationJson
        if (att != null) {
            try {
                val j = org.json.JSONObject(att)
                val docH = j.getJSONObject("document").getString("doc_hash")
                docHash = "${docH.take(6)}…${docH.takeLast(4)}"
                val sig = j.getJSONObject("signature_data").getString("sigma")
                sigmaShort = "${sig.take(6)}…${sig.takeLast(4)}"
                certSize = "${att.length} octets"
            } catch (_: Exception) {}
        }

        // Certificate card
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(12), dp(12), dp(12), dp(12))
            background = GradientDrawable().apply { setColor(PURPLE_L); setStroke(dp(1), purpleBorder()); cornerRadius = dp(4).toFloat() }
            layoutParams = lp().apply { bottomMargin = dp(14) }
        }
        card.addView(certRow("Signataire", "Vous · ${Build.MANUFACTURER} ${Build.MODEL}", PURPLE))
        card.addView(certRow("Référence", pendingDocRef, PURPLE))
        card.addView(certRow("Horodatage τ", tau.toString(), PURPLE))
        card.addView(certRow("H(doc)", docHash, PURPLE))
        card.addView(certRow("σ", sigmaShort, PURPLE))
        card.addView(certRow("Taille cert.", certSize, PURPLE))
        body.addView(card)

        body.addView(cta("Envoyer le certificat par email", PURPLE) { shareAttestation() })
        body.addView(spacer(8))
        body.addView(ctaOutline("Enregistrer localement") { saveAttestationLocal() })
        body.addView(spacer(8))
        body.addView(ctaOutline("Retour à l'accueil") {
            decryptedPdfBytes = null; pendingPayloadJson = null; lastAttestationJson = null
            showScreen(Screen.HOME)
        })

        root.addView(body)
        root.addView(dots(5, 5, PURPLE))
        container.addView(scroll(root))
    }

    // ════════════════════════════════════════════════════════════════════
    //  6. SEND — Envoyer un document
    // ════════════════════════════════════════════════════════════════════

    /** Screen A — select the PDF document to send. */
    /** Écran SEND_DOC — last step before sending. Recipient is already pinned via
     *  selectedRecipient set in the Sésame profile. User picks a PDF here and
     *  Continuer triggers the encrypt-and-send flow directly. */
    private fun buildSendDoc(): LinearLayout {
        val root = screenRoot()
        root.addView(accentBar(PURPLE))
        root.addView(topBar("Sésame", PURPLE, stepLabel("Envoyer")))

        val body = bodyPad()
        body.addView(backLink { showScreen(Screen.SESAME_PROFILE) })
        body.addView(titleSerif("Sélectionnez\nle document", PURPLE))
        body.addView(spacer(14))

        val r = selectedRecipient
        if (r != null) {
            val model = extractModel(r.optString("device", ""), r.optString("markers", "{}"))
            val short4 = shortIdSuffix(r.optString("id_short", ""), r.optString("encryption_pk", ""))
            val name = r.optString("name", "Votre Sésame")
            body.addView(sesameInfoBlock(
                "Seul le $model ...$short4 de $name peut ouvrir ce document. Même sur sa boîte mail, même sur un autre téléphone — illisible."
            ))
            body.addView(spacer(14))
        }

        val pdfLabel = if (selectedPdfBytes != null) "✓ ${selectedPdfName} (${selectedPdfBytes!!.size} octets)" else "Sélectionnez un fichier PDF"
        body.addView(pickerCard("📄", pdfLabel, "Parcourir") {
            pickPdfLauncher.launch(arrayOf("application/pdf"))
        })
        body.addView(spacer(18))

        val signBtn = ctaTall("Envoyer pour signature", PURPLE) { doSendDocument(mode = "signature") }
        if (selectedPdfBytes == null) { signBtn.alpha = 0.4f; signBtn.isEnabled = false }
        body.addView(signBtn)
        body.addView(modeSubtitle("Votre Sésame devra lire et signer. Vous recevrez un certificat."))
        body.addView(sizeHintLine())
        body.addView(spacer(12))

        val simpleBtn = ctaTall("Envoyer simplement", GREEN) { doSendDocument(mode = "readonly") }
        if (selectedPdfBytes == null) { simpleBtn.alpha = 0.4f; simpleBtn.isEnabled = false }
        body.addView(simpleBtn)
        body.addView(modeSubtitle("Votre Sésame pourra lire le document. Aucune signature requise."))
        body.addView(sizeHintLine())

        root.addView(body)
        return root
    }

    private fun modeSubtitle(text: String) = TextView(this).apply {
        this.text = text
        typeface = MONO
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        setTextColor(FG3)
        layoutParams = lp().apply { topMargin = dp(6); bottomMargin = dp(2) }
    }

    private fun sizeHintLine() = TextView(this).apply {
        text = "Documents jusqu'à 10 MB · Fichiers volumineux bientôt"
        typeface = MONO
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
        setTextColor(FG4)
        layoutParams = lp().apply { topMargin = dp(2) }
    }

    /** Both send modes require sender biometrics to confirm intent. The unwrapped key
     *  is not used for signing — it just proves the sender is present and bound to the
     *  device. The recipient is the one who signs (when mode == "signature"). */
    private fun doSendDocument(mode: String) {
        val pdf = selectedPdfBytes ?: return
        val recipient = selectedRecipient ?: return
        val recipientEncPk = recipient.getString("encryption_pk")
        val recipientName = recipient.optString("name", "Votre Sésame")

        val blobB64 = prefs().getString("signing_sk_blob", "") ?: ""
        val blob = android.util.Base64.decode(blobB64, android.util.Base64.DEFAULT)
        val bioTitle = if (mode == "signature") "Envoyer pour signature" else "Envoyer simplement"
        val bioSubtitle = "Confirmez l'envoi avec votre empreinte"
        BiometricHelper.unwrapKey(this, bioTitle, bioSubtitle, blob,
            onSuccess = { combined ->
                try {
                    val payloadJson = AuthentixCore.encryptFor(recipientEncPk, pdf)
                    if (payloadJson.contains("\"error\"")) {
                        Toast.makeText(this, "Erreur chiffrement : $payloadJson", Toast.LENGTH_LONG).show()
                        return@unwrapKey
                    }

                    val docRef = "DOC-${System.currentTimeMillis()}"
                    val myPk = prefs().getString("signing_pk", "") ?: ""
                    val envType = if (mode == "signature") "document" else "document_readonly"
                    val envelope = org.json.JSONObject().apply {
                        put("version", 2)
                        put("type", envType)
                        put("payload", org.json.JSONObject(payloadJson))
                        put("sender", org.json.JSONObject().apply {
                            put("name", "${Build.MANUFACTURER} ${Build.MODEL}")
                            put("signing_pk", myPk)
                        })
                        put("recipient", org.json.JSONObject().apply {
                            put("name", recipientName)
                            put("encryption_pk", recipientEncPk)
                        })
                        put("ref", docRef)
                        put("subject", selectedPdfName)
                    }

                    val file = java.io.File(cacheDir, "$docRef.sesame")
                    file.writeText(envelope.toString())
                    val uri = androidx.core.content.FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
                    val subjectLine = if (mode == "signature")
                        "Document Sésame (à signer) — $docRef"
                    else
                        "Document Sésame — $docRef"
                    val bodyLine = if (mode == "signature")
                        "Document chiffré envoyé via SÉSAME.\nVotre Sésame devra le lire et le signer, puis vous renverra un certificat."
                    else
                        "Document chiffré envoyé via SÉSAME.\nSeul votre Sésame peut l'ouvrir. Aucune signature n'est attendue."
                    val intent = Intent(Intent.ACTION_SEND).apply {
                        type = "application/x-sesame"
                        putExtra(Intent.EXTRA_STREAM, uri)
                        putExtra(Intent.EXTRA_SUBJECT, subjectLine)
                        putExtra(Intent.EXTRA_TEXT, bodyLine)
                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    }
                    val chooserTitle = if (mode == "signature")
                        "Envoyer le document à signer"
                    else
                        "Envoyer le document"
                    startActivity(Intent.createChooser(intent, chooserTitle))

                    selectedPdfBytes = null; selectedPdfName = ""; selectedRecipient = null
                    val toastMsg = if (mode == "signature")
                        "✓ Document envoyé — en attente de signature"
                    else
                        "✓ Document envoyé — lecture seule"
                    Toast.makeText(this, toastMsg, Toast.LENGTH_LONG).show()
                } catch (e: Exception) {
                    Toast.makeText(this, "Erreur : ${e.message}", Toast.LENGTH_LONG).show()
                } finally {
                    Arrays.fill(combined, 0)
                }
            },
            onError = { msg -> Toast.makeText(this, "Erreur bio : $msg", Toast.LENGTH_LONG).show() },
            onInvalidated = { handleKeyInvalidated() }
        )
    }

    // ════════════════════════════════════════════════════════════════════
    //  7. CONTACTS — Carnet d'adresses
    // ════════════════════════════════════════════════════════════════════

    /** Mes Sésames — list of verified contacts. Tap a row to open that Sésame's profile. */
    private fun buildContacts(): LinearLayout {
        val root = screenRoot()
        root.addView(accentBar(PURPLE))
        root.addView(topBar("Sésame", PURPLE, stepLabel("Mes Sésames")))

        val body = bodyPad()
        body.addView(backLink { showScreen(Screen.HOME) })
        body.addView(titleSerif("Mes\nSésames", PURPLE))
        body.addView(spacer(14))

        val contacts = loadContacts()
        if (contacts.length() == 0) {
            val emptyCard = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER
                setPadding(dp(16), dp(24), dp(16), dp(24))
                background = card_bg()
                layoutParams = lp().apply { bottomMargin = dp(14) }
            }
            emptyCard.addView(TextView(this).apply {
                text = "Aucun Sésame pour l'instant"
                typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f); setTextColor(FG4); gravity = Gravity.CENTER
            })
            body.addView(emptyCard)
        } else {
            for (i in 0 until contacts.length()) {
                val c = contacts.getJSONObject(i)
                val isObsolete = c.optBoolean("obsolete", false)
                val card = LinearLayout(this).apply {
                    orientation = LinearLayout.VERTICAL; setPadding(dp(14), dp(14), dp(14), dp(14))
                    background = GradientDrawable().apply {
                        setColor(if (isObsolete) Color.parseColor("#fff6e0") else PURPLE_L)
                        setStroke(dp(1), if (isObsolete) Color.parseColor("#b88a20") else purpleBorder())
                        cornerRadius = dp(4).toFloat()
                    }
                    layoutParams = lp().apply { bottomMargin = dp(8) }
                    isClickable = true; isFocusable = true
                    setOnClickListener {
                        selectedRecipient = c
                        showScreen(Screen.SESAME_PROFILE)
                    }
                }
                val color = if (isObsolete) Color.parseColor("#b88a20") else PURPLE
                val mark = if (isObsolete) "⚠️" else "✅"
                card.addView(TextView(this).apply {
                    text = "$mark ${c.getString("name")}"
                    typeface = SERIF_B; setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f); setTextColor(color)
                    layoutParams = lp().apply { bottomMargin = dp(4) }
                })
                card.addView(TextView(this).apply {
                    text = "${c.optString("device", "—")}  ·  ${c.optString("id_short", "—")}"
                    typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f); setTextColor(FG3)
                    layoutParams = lp()
                })
                if (isObsolete) {
                    card.addView(TextView(this).apply {
                        text = "Clé obsolète — demandez à ce Sésame de renvoyer son kit"
                        typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f); setTextColor(Color.parseColor("#b88a20"))
                        layoutParams = lp().apply { topMargin = dp(6) }
                    })
                }
                body.addView(card)
            }
        }
        body.addView(spacer(10))
        body.addView(ctaOutline("+ Inviter un Sésame") { startInviteFlow() })

        root.addView(body)
        return root
    }

    /** Profil d'un Sésame — the only place Envoyer/Recevoir buttons appear. */
    private fun buildSesameProfile(): LinearLayout {
        val root = screenRoot()
        root.addView(accentBar(PURPLE))
        root.addView(topBar("Sésame", PURPLE, stepLabel("Sésame")))

        val body = bodyPad()
        body.addView(backLink { showScreen(Screen.CONTACTS) })

        val r = selectedRecipient
        if (r == null) {
            body.addView(sub("Aucun Sésame sélectionné."))
            root.addView(body)
            return root
        }
        val isObsolete = r.optBoolean("obsolete", false)
        val color = if (isObsolete) Color.parseColor("#b88a20") else PURPLE

        body.addView(titleSerif(r.optString("name", "Sésame"), color))
        body.addView(TextView(this).apply {
            text = "${r.optString("device", "—")}  ·  ${r.optString("id_short", "—")}"
            typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f); setTextColor(FG3)
            layoutParams = lp().apply { bottomMargin = dp(4) }
        })
        if (isObsolete) {
            body.addView(sesameInfoBlock(
                "Clé obsolète — demandez à ce Sésame de renvoyer son kit avant de lui envoyer un document."
            ))
        }
        body.addView(spacer(24))

        body.addView(ctaTall("Envoyer un document", PURPLE) {
            if (isObsolete) {
                Toast.makeText(this, "Clé obsolète — réimportez d'abord son identité", Toast.LENGTH_LONG).show()
            } else {
                selectedPdfBytes = null; selectedPdfName = ""
                showScreen(Screen.SEND_DOC)
            }
        })
        body.addView(spacer(12))
        body.addView(ctaTall("Recevoir un document", PURPLE) {
            receiveSesameLauncher.launch(arrayOf("*/*"))
        })

        root.addView(body)
        return root
    }

    /** Invite screen — offers SMS + email with .sesame-id attached. */
    private fun buildInvite(): LinearLayout {
        val root = screenRoot()
        root.addView(accentBar(PURPLE))
        root.addView(topBar("Sésame", PURPLE, stepLabel("Inviter")))

        val body = bodyPad()
        body.addView(backLink { showScreen(Screen.HOME) })
        body.addView(titleSerif("Inviter\nun Sésame", PURPLE))
        body.addView(spacer(14))
        body.addView(sesameInfoBlock(
            "Envoyez-lui un lien pour qu'il installe Sésame, puis demandez-lui son identité en retour."
        ))
        body.addView(spacer(18))

        body.addView(ctaTall("Inviter un Sésame", PURPLE) { startInviteFlow() })

        root.addView(body)
        return root
    }

    /** Chains SMS → Email → HOME. Step 1 fires SMS; onResume detects return and fires
     *  the email intent; next onResume shows a toast and lands on HOME. */
    private fun startInviteFlow() {
        val kitJson = prefs().getString("signed_kit_json", "") ?: ""
        if (kitJson.isEmpty()) {
            Toast.makeText(this, "Kit Sésame indisponible — recréez votre identité", Toast.LENGTH_LONG).show()
            return
        }
        pendingInviteStep = 1
        sendInviteSms()
    }

    private fun sendInviteSms() {
        val body = "Installez Sésame :\n" +
            "- Site web : https://authentix-sign.tech\n" +
            "- Google Play : https://play.google.com/store/apps/details?id=app.authentixsign\n" +
            "Ouvrez ensuite le fichier que je vous envoie\n" +
            "par email pour m'ajouter à vos Sésames."
        try {
            val intent = Intent(Intent.ACTION_SENDTO).apply {
                data = android.net.Uri.parse("smsto:")
                putExtra("sms_body", body)
            }
            startActivity(intent)
        } catch (e: Exception) {
            // No SMS app — skip straight to the email step so the flow can still complete.
            Toast.makeText(this, "Aucune app SMS — envoi par email uniquement", Toast.LENGTH_SHORT).show()
            pendingInviteStep = 2
            container.post { sendInviteEmailWithKit() }
        }
    }

    private fun sendInviteEmailWithKit() {
        val kitJson = prefs().getString("signed_kit_json", "") ?: ""
        if (kitJson.isEmpty()) {
            Toast.makeText(this, "Kit Sésame indisponible", Toast.LENGTH_LONG).show()
            pendingInviteStep = 0
            return
        }
        try {
            val file = java.io.File(cacheDir, "mon-identite.sesame-id")
            if (file.exists()) file.delete()
            file.writeText(kitJson, Charsets.UTF_8)
            val uri = androidx.core.content.FileProvider.getUriForFile(
                this, "$packageName.fileprovider", file,
            )
            val body = "Pour m'ajouter à tes contacts Sésame :\n" +
                "1. Installe l'app : https://authentix-sign.tech\n" +
                "2. Ouvre le fichier joint — je serai\n" +
                "   automatiquement ajouté à tes Sésames."
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "*/*"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "Rejoins-moi sur Sésame")
                putExtra(Intent.EXTRA_TEXT, body)
                putExtra(Intent.EXTRA_EMAIL, arrayOf<String>())
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                clipData = android.content.ClipData.newRawUri("mon-identite.sesame-id", uri)
            }
            pendingKitFile = file
            startActivity(Intent.createChooser(intent, "Inviter par email"))
        } catch (e: Exception) {
            android.util.Log.e("SesameShare", "sendInviteEmailWithKit failed", e)
            Toast.makeText(this, "Erreur : ${e.message}", Toast.LENGTH_LONG).show()
            pendingInviteStep = 0
        }
    }

    /** Terminate the invite chain: toast + unconditional navigation to HOME.
     *  Persists onboarding_done (idempotent) and increments invite_count so HOME
     *  can demote the primary "Inviter" CTA once the user has invited at least
     *  once. Never routes back to the INVITE screen or the onboarding pager —
     *  that caused an apparent loop where users re-invited from "Ouvre-toi !". */
    private fun finishInviteFlow() {
        Toast.makeText(this, "Invitation envoyée ✓", Toast.LENGTH_LONG).show()
        prefs().edit().apply {
            putBoolean("onboarding_done", true)
            putInt("invite_count", prefs().getInt("invite_count", 0) + 1)
        }.apply()
        onOnboarding = false
        onboardingPager = null
        showScreen(Screen.HOME)
    }

    // ════════════════════════════════════════════════════════════════════
    //  8. MY_ID — Mon identité / Mon QR
    // ════════════════════════════════════════════════════════════════════

    private fun buildMyId(): LinearLayout {
        val root = screenRoot()
        root.addView(accentBar(PURPLE))
        root.addView(topBar("Sésame", PURPLE, stepLabel("Mon identité")))

        val body = bodyPad()
        body.addView(backLink { showScreen(Screen.HOME) })

        val spk = prefs().getString("signing_pk", "") ?: ""
        val epk = prefs().getString("encryption_pk", "") ?: ""
        val kitJson = prefs().getString("signed_kit_json", "") ?: fallbackUnsignedKit(spk, epk)
        val device = "${Build.MANUFACTURER} ${Build.MODEL}".trim()
        val shortId = shortIdSuffix("", epk)
        val createdAt = prefs().getLong("id_created_at", 0L)

        // ── SECTION 1 — Bandeau explication ──────────────────────────────
        body.addView(sesameInfoBlock(
            "Votre identité numérique est votre adresse Sésame. Partagez-la pour que vos Sésames puissent vous envoyer des documents que vous seul pouvez ouvrir."
        ))
        body.addView(spacer(16))

        // ── SECTION 2 — Mon QR code ──────────────────────────────────────
        body.addView(eyebrow("À FAIRE SCANNER PAR VOS CONTACTS"))
        body.addView(titleSerif("Mon QR d'identité", PURPLE))
        body.addView(spacer(10))
        val qrBitmap = generateQr(kitJson)
        if (qrBitmap != null) {
            val qrContainer = LinearLayout(this).apply {
                gravity = Gravity.CENTER; setPadding(dp(16), dp(16), dp(16), dp(16))
                background = GradientDrawable().apply { setColor(WHITE); setStroke(dp(1), BORDER); cornerRadius = dp(4).toFloat() }
                layoutParams = lp().apply { bottomMargin = dp(10) }
            }
            qrContainer.addView(android.widget.ImageView(this).apply {
                setImageBitmap(qrBitmap); scaleType = android.widget.ImageView.ScaleType.FIT_CENTER
                layoutParams = LinearLayout.LayoutParams(dp(240), dp(240))
            })
            body.addView(qrContainer)
        }
        val qrSubCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(12), dp(10), dp(12), dp(10))
            background = GradientDrawable().apply { setColor(PURPLE_L); cornerRadius = dp(4).toFloat() }
            layoutParams = lp().apply { bottomMargin = dp(18) }
        }
        qrSubCard.addView(certRow("Nom appareil", device, PURPLE))
        qrSubCard.addView(certRow("Identifiant", "...$shortId", PURPLE))
        qrSubCard.addView(certRow("Clé tronquée", trunc(spk), PURPLE))
        body.addView(qrSubCard)

        // "Partager mon identité" section removed — the unified invite flow
        // (startInviteFlow) is now the only entry point for sharing identity,
        // accessible from onboarding and HOME. QR fullscreen stays here as a
        // display-only helper.
        body.addView(ctaOutline("Afficher mon QR en grand") { showQrFullscreen(kitJson) })
        body.addView(spacer(24))

        // ── SECTION 4 — Mes informations ─────────────────────────────────
        body.addView(eyebrow("Mes informations"))
        body.addView(spacer(6))
        val infoCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(14), dp(14), dp(14), dp(14))
            background = GradientDrawable().apply {
                setColor(WHITE); setStroke(1, BORDER); cornerRadius = dp(8).toFloat()
            }
            layoutParams = lp().apply { bottomMargin = dp(24) }
        }
        infoCard.addView(certRow("Appareil", device, PURPLE))
        infoCard.addView(certRow("Identifiant", "...$shortId", PURPLE))
        infoCard.addView(certRow("Algorithme", "ML-DSA-65 (post-quantique)", PURPLE))
        infoCard.addView(certRow("Clé", trunc(spk), PURPLE))
        infoCard.addView(certRow("Créée le", if (createdAt > 0) formatDateTime(createdAt) else "—", PURPLE))
        infoCard.addView(certRow("Statut", "✅ Active", GREEN))
        body.addView(infoCard)

        // Discreet link to the SÉSAME manifesto (brand promise), sits between the
        // info card and the danger zone so it stays low-visibility but discoverable.
        body.addView(TextView(this).apply {
            text = "[ Notre engagement ]"
            typeface = MONO
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            setTextColor(Color.parseColor("#aaa89e"))
            gravity = Gravity.CENTER
            setPadding(dp(10), dp(6), dp(10), dp(14))
            isClickable = true; isFocusable = true
            setOnClickListener { showManifesto(fromMyId = true) }
            layoutParams = lp()
        })

        // ── SECTION 5 — Zone danger ──────────────────────────────────────
        body.addView(View(this).apply {
            setBackgroundColor(BORDER)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 1).apply { bottomMargin = dp(10) }
        })
        body.addView(eyebrow("Zone sensible").apply { setTextColor(RED) })
        body.addView(spacer(6))
        body.addView(Button(this).apply {
            text = "⚠️ RÉINITIALISER MON IDENTITÉ"
            typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f); setTextColor(RED)
            letterSpacing = 0.1f; isAllCaps = false; stateListAnimator = null; elevation = 0f
            setPadding(dp(12), dp(12), dp(12), dp(12))
            background = GradientDrawable().apply { setColor(Color.TRANSPARENT); setStroke(dp(1), RED); cornerRadius = dp(2).toFloat() }
            layoutParams = lp()
            setOnClickListener { confirmUserResetIdentity() }
        })

        root.addView(body)
        return root
    }

    private fun formatDateTime(millis: Long): String {
        val sdf = java.text.SimpleDateFormat("dd/MM/yyyy 'à' HH:mm", java.util.Locale.FRANCE)
        return sdf.format(java.util.Date(millis))
    }

    /** File currently attached to a pending share intent. Deleted on the next onResume —
     *  we can't delete immediately because the receiving app reads the URI asynchronously.
     *  Written by sendInviteEmailWithKit() when the email step of startInviteFlow() fires. */
    private var pendingKitFile: java.io.File? = null

    override fun onResume() {
        super.onResume()
        // The activity is NOT recreated when an external Intent (email chooser, SMS app)
        // returns — all activity state (onOnboarding, onboardingPager, currentScreen,
        // MY_ID data) is preserved, so the user sees exactly the screen they left.
        pendingKitFile?.let { f ->
            try { if (f.exists()) f.delete() } catch (_: Exception) {}
            pendingKitFile = null
        }
        // Chain the invite flow: SMS returned → fire email; email returned → HOME.
        when (pendingInviteStep) {
            1 -> {
                pendingInviteStep = 2
                container.post { sendInviteEmailWithKit() }
            }
            2 -> {
                pendingInviteStep = 0
                finishInviteFlow()
            }
        }
    }

    private fun fallbackUnsignedKit(spk: String, epk: String): String {
        return org.json.JSONObject().apply {
            put("signing_pk", spk)
            put("encryption_pk", epk)
            put("device", "${Build.MANUFACTURER} ${Build.MODEL}")
        }.toString()
    }

    private fun generateQr(data: String): android.graphics.Bitmap? {
        return try {
            val hints = mapOf(com.google.zxing.EncodeHintType.MARGIN to 1)
            val matrix = com.google.zxing.qrcode.QRCodeWriter().encode(
                data, com.google.zxing.BarcodeFormat.QR_CODE, 512, 512, hints
            )
            val w = matrix.width; val h = matrix.height
            val bmp = android.graphics.Bitmap.createBitmap(w, h, android.graphics.Bitmap.Config.RGB_565)
            for (x in 0 until w) for (y in 0 until h)
                bmp.setPixel(x, y, if (matrix.get(x, y)) Color.parseColor("#1a1a18") else Color.parseColor("#f5f4f0"))
            bmp
        } catch (e: Exception) { null }
    }

    private fun copyableKey(label: String, value: String): TextView {
        return TextView(this).apply {
            text = "$label:\n$value"
            typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f); setTextColor(FG3)
            setLineSpacing(0f, 1.4f); setTextIsSelectable(true)
            setPadding(dp(10), dp(8), dp(10), dp(8))
            background = card_bg()
            layoutParams = lp()
        }
    }

    private fun shareKit(kitJson: String) {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "SÉSAME — Ma clé publique")
            putExtra(Intent.EXTRA_TEXT, kitJson)
        }
        startActivity(Intent.createChooser(intent, "Partager mon identité"))
    }

    private fun exportKit(kitJson: String) {
        try {
            val file = java.io.File(cacheDir, "mon-identite.sesame-id")
            file.writeText(kitJson)
            val uri = androidx.core.content.FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "application/x-sesame"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "SÉSAME — Mon identité")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(intent, "Exporter .sesame-id"))
        } catch (e: Exception) {
            Toast.makeText(this, "Erreur export : ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    // ════════════════════════════════════════════════════════════════════
    //  HELPERS — PDF rendering, sharing, crypto display
    // ════════════════════════════════════════════════════════════════════

    private fun sha3Hex(data: ByteArray): String {
        // SHA3-256 available on API 28+; fallback to SHA-256 for display only
        val algo = if (Build.VERSION.SDK_INT >= 28) "SHA3-256" else "SHA-256"
        val md = java.security.MessageDigest.getInstance(algo)
        return md.digest(data).joinToString("") { "%02x".format(it) }
    }

    private fun renderPdfFirstPage(pdfBytes: ByteArray): android.graphics.Bitmap? {
        if (Build.VERSION.SDK_INT < 21) return null
        return try {
            val tmpFile = java.io.File(cacheDir, "tmp_preview.pdf")
            tmpFile.writeBytes(pdfBytes)
            val fd = android.os.ParcelFileDescriptor.open(tmpFile, android.os.ParcelFileDescriptor.MODE_READ_ONLY)
            val renderer = android.graphics.pdf.PdfRenderer(fd)
            if (renderer.pageCount == 0) { renderer.close(); fd.close(); return null }
            val page = renderer.openPage(0)
            val scale = 2
            val bmp = android.graphics.Bitmap.createBitmap(page.width * scale, page.height * scale, android.graphics.Bitmap.Config.ARGB_8888)
            bmp.eraseColor(Color.WHITE)
            page.render(bmp, null, null, android.graphics.pdf.PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
            page.close(); renderer.close(); fd.close()
            tmpFile.delete()
            bmp
        } catch (_: Exception) { null }
    }

    private fun shareAttestation() {
        val att = lastAttestationJson ?: return
        try {
            val file = java.io.File(cacheDir, "${pendingDocRef}.attestation.json")
            file.writeText(att)
            val uri = androidx.core.content.FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "application/json"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "SÉSAME — Attestation $pendingDocRef")
                putExtra(Intent.EXTRA_TEXT, "Attestation de signature Sésame\nRéférence : $pendingDocRef\nSigné sur ${Build.MANUFACTURER} ${Build.MODEL}")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(intent, "Envoyer l'attestation"))
        } catch (e: Exception) {
            Toast.makeText(this, "Erreur envoi : ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun saveAttestationLocal() {
        val att = lastAttestationJson ?: return
        try {
            val dir = getExternalFilesDir(null) ?: filesDir
            val file = java.io.File(dir, "${pendingDocRef}.attestation.json")
            file.writeText(att)
            Toast.makeText(this, "Enregistré : ${file.name}", Toast.LENGTH_LONG).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Erreur : ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    // ════════════════════════════════════════════════════════════════════
    //  DESIGN SYSTEM — Composants réutilisables
    // ════════════════════════════════════════════════════════════════════

    private fun dp(n: Int) = (n * resources.displayMetrics.density).toInt()
    private fun lp() = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)

    private fun screenRoot() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL; setBackgroundColor(BG)
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
    }

    private fun bodyPad() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL; setPadding(dp(18), dp(0), dp(18), dp(14))
        layoutParams = lp()
    }

    private fun scroll(child: View) = ScrollView(this).apply {
        setBackgroundColor(BG); layoutParams = FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
        addView(child)
    }

    // ── Bars ────────────────────────────────────────────────────────────

    private fun accentBar(color: Int) = View(this).apply {
        setBackgroundColor(color); layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, dp(3))
    }

    private fun topBar(product: String, color: Int, right: View): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(18), dp(14), dp(18), dp(10))
            addView(TextView(this@MainActivity).apply {
                text = product; typeface = SERIF_B; setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f); setTextColor(color)
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
            })
            addView(right)
        }
    }

    // ── Typography ──────────────────────────────────────────────────────

    private fun eyebrow(text: String) = TextView(this).apply {
        this.text = text.uppercase(); typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f); setTextColor(FG4)
        letterSpacing = 0.16f; layoutParams = lp().apply { bottomMargin = dp(6) }
    }

    private fun titleSerif(text: String, color: Int) = TextView(this).apply {
        this.text = text; typeface = SERIF_B; setTextSize(TypedValue.COMPLEX_UNIT_SP, 32f); setTextColor(color)
        setLineSpacing(0f, 1.05f); layoutParams = lp().apply { bottomMargin = dp(12) }
    }

    private fun sub(text: String) = TextView(this).apply {
        this.text = text; typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f); setTextColor(FG3)
        setLineSpacing(0f, 1.6f); layoutParams = lp().apply { bottomMargin = dp(14) }
    }

    private fun guideText(text: String) = TextView(this).apply {
        this.text = text; setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f); setTextColor(FG2)
        setLineSpacing(0f, 1.5f)
        setPadding(dp(12), dp(10), dp(12), dp(10))
        background = GradientDrawable().apply { setColor(Color.parseColor("#f0efe8")); cornerRadius = dp(4).toFloat() }
        layoutParams = lp().apply { bottomMargin = dp(10) }
    }

    /** Info block with purple left border (#6655c0) on #f0eefb background. */
    private fun sesameInfoBlock(text: String) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        background = GradientDrawable().apply { setColor(Color.parseColor("#f0eefb")); cornerRadius = dp(2).toFloat() }
        layoutParams = lp().apply { bottomMargin = dp(10) }
        addView(View(this@MainActivity).apply {
            setBackgroundColor(Color.parseColor("#6655c0"))
            layoutParams = LinearLayout.LayoutParams(dp(2), MATCH_PARENT)
        })
        addView(TextView(this@MainActivity).apply {
            this.text = text
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            setTextColor(FG2)
            setLineSpacing(0f, 1.5f)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        })
    }

    /** Monospace note: #6a6860 (FG3), 11sp, tight line spacing — used for cryptographic UX explainers. */
    private fun monoNote(text: String) = TextView(this).apply {
        this.text = text
        typeface = MONO
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
        setTextColor(FG3)
        setLineSpacing(0f, 1.5f)
        layoutParams = lp().apply { bottomMargin = dp(12); topMargin = dp(4) }
    }

    private fun spacer(h: Int) = View(this).apply { layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, dp(h)) }

    // ── Badges & labels ─────────────────────────────────────────────────

    private fun badge(text: String, bg: Int, fg: Int) = TextView(this).apply {
        this.text = text; typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f); setTextColor(fg)
        letterSpacing = 0.08f; setPadding(dp(10), dp(4), dp(10), dp(4))
        background = GradientDrawable().apply { setColor(bg); cornerRadius = dp(2).toFloat() }
    }

    private fun stepLabel(text: String) = TextView(this).apply {
        this.text = text.uppercase(); typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f); setTextColor(FG4); letterSpacing = 0.1f
    }

    // ── Buttons ─────────────────────────────────────────────────────────

    private fun cta(label: String, bgColor: Int, onClick: () -> Unit) = Button(this).apply {
        text = label.uppercase(); typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f); setTextColor(WHITE)
        letterSpacing = 0.1f; isAllCaps = false; stateListAnimator = null; elevation = 0f
        setPadding(dp(12), dp(12), dp(12), dp(12)); setBackgroundColor(bgColor)
        layoutParams = lp(); setOnClickListener { onClick() }
    }

    private fun ctaOutline(label: String, onClick: () -> Unit) = Button(this).apply {
        text = label.uppercase(); typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f); setTextColor(FG3)
        letterSpacing = 0.1f; isAllCaps = false; stateListAnimator = null; elevation = 0f
        setPadding(dp(12), dp(12), dp(12), dp(12))
        background = GradientDrawable().apply { setColor(Color.TRANSPARENT); setStroke(1, BORDER) }
        layoutParams = lp(); setOnClickListener { onClick() }
    }

    private fun backLink(onClick: () -> Unit) = TextView(this).apply {
        text = "← Retour"; typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f); setTextColor(PURPLE)
        setPadding(0, 0, 0, dp(14)); setOnClickListener { onClick() }
        layoutParams = LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT)
    }

    // ── Bio zone (with fingerprint icon) ────────────────────────────────

    private fun bioZoneFull(bg: Int, border: Int, accent: Int, label: String, intense: Boolean, onClick: () -> Unit): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER
            setPadding(dp(20), dp(20), dp(20), dp(20))
            background = GradientDrawable().apply { setColor(bg); setStroke(dp(1), border); cornerRadius = dp(6).toFloat() }
            layoutParams = lp().apply { bottomMargin = dp(14) }
            isClickable = true
            isFocusable = true

            addView(FingerprintView(this@MainActivity, accent, intense).apply {
                layoutParams = LinearLayout.LayoutParams(dp(40), dp(40)).apply { bottomMargin = dp(8) }
                isClickable = false
            })
            addView(TextView(this@MainActivity).apply {
                text = label.uppercase(); typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f); setTextColor(accent); letterSpacing = 0.1f
                isClickable = false
            })
            setOnClickListener { onClick() }
        }
    }

    // ── QR zone ─────────────────────────────────────────────────────────

    private fun qrZone(): LinearLayout {
        return LinearLayout(this).apply {
            gravity = Gravity.CENTER; setPadding(dp(16), dp(16), dp(16), dp(16))
            background = card_bg()
            layoutParams = lp().apply { bottomMargin = dp(0) }

            addView(QrPlaceholderView(this@MainActivity, PURPLE).apply {
                layoutParams = LinearLayout.LayoutParams(dp(80), dp(80))
            })
        }
    }

    // ── Document preview ────────────────────────────────────────────────

    private fun docPreview(lines: Int): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(14), dp(14), dp(14), dp(14))
            background = card_bg()
            layoutParams = lp().apply { bottomMargin = dp(14) }

            for (i in 0 until lines) {
                val w = when { i % 4 == 2 -> 0.6f; i % 4 == 3 -> 0.4f; else -> 1f }
                addView(View(this@MainActivity).apply {
                    background = GradientDrawable().apply { setColor(Color.parseColor("#0f000000")); cornerRadius = dp(2).toFloat() }
                    layoutParams = LinearLayout.LayoutParams(
                        if (w < 1f) (resources.displayMetrics.widthPixels * w * 0.65f).toInt() else MATCH_PARENT,
                        dp(6)
                    ).apply { bottomMargin = dp(5) }
                })
                if (i % 4 == 3 && i < lines - 1) addView(spacer(3))
            }
        }
    }

    // ── Picker card (send screen) ───────────────────────────────────────

    private fun pickerCard(icon: String, text: String, action: String, onClick: () -> Unit): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(16), dp(14), dp(16)); background = card_bg()
            layoutParams = lp()

            addView(TextView(this@MainActivity).apply { this.text = icon; setTextSize(TypedValue.COMPLEX_UNIT_SP, 20f); setPadding(0, 0, dp(12), 0) })
            addView(TextView(this@MainActivity).apply {
                this.text = text; typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f); setTextColor(FG3)
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
            })
            addView(TextView(this@MainActivity).apply {
                this.text = action.uppercase(); typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f); setTextColor(PURPLE); letterSpacing = 0.1f
            })
            setOnClickListener { onClick() }
        }
    }

    private fun fieldCard(label: String, hint: String): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(14), dp(12), dp(14), dp(12))
            background = card_bg(); layoutParams = lp()

            addView(TextView(this@MainActivity).apply {
                text = label.uppercase(); typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f); setTextColor(FG4); letterSpacing = 0.12f
                layoutParams = lp().apply { bottomMargin = dp(4) }
            })
            addView(TextView(this@MainActivity).apply {
                this.text = hint; typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f); setTextColor(FG4)
            })
        }
    }

    // ── Certificate row ─────────────────────────────────────────────────

    private fun certRow(label: String, value: String, valColor: Int): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            layoutParams = lp().apply { bottomMargin = dp(5) }
            addView(TextView(this@MainActivity).apply { text = label; typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f); setTextColor(FG4); layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f) })
            addView(TextView(this@MainActivity).apply { text = value; typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f); setTextColor(valColor) })
        }
    }

    // ── Progress dots ───────────────────────────────────────────────────

    private fun dots(active: Int, total: Int, color: Int) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER; setPadding(0, dp(10), 0, dp(14))
        for (i in 1..total) {
            addView(View(this@MainActivity).apply {
                background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(if (i <= active) color else BORDER) }
                layoutParams = LinearLayout.LayoutParams(dp(6), dp(6)).apply { setMargins(dp(2), 0, dp(2), 0) }
            })
        }
    }

    // ── Timer ───────────────────────────────────────────────────────────

    private fun timerLabel(text: String) = TextView(this).apply {
        this.text = text; typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f); setTextColor(FG4)
    }

    // ── Shared ──────────────────────────────────────────────────────────

    private fun card_bg() = GradientDrawable().apply { setColor(WHITE); setStroke(1, BORDER); cornerRadius = dp(4).toFloat() }
    private fun purpleBorder() = Color.argb(46, 102, 85, 192)
    private fun purpleBorderIntense() = Color.argb(77, 102, 85, 192)
    private fun goldBorder() = Color.argb(46, 154, 122, 40)
    private fun trunc(b64: String) = if (b64.length > 12) "${b64.take(6)}…${b64.takeLast(4)}" else b64

    /** Extract the device model. Prefers markers.model; falls back to device string minus brand. */
    private fun extractModel(device: String, markersJson: String): String {
        try {
            val m = org.json.JSONObject(markersJson)
            val model = m.optString("model", "").trim()
            if (model.isNotEmpty()) return model
            val brand = m.optString("brand", "").trim()
            if (brand.isNotEmpty() && device.startsWith(brand)) {
                return device.removePrefix(brand).trim().ifEmpty { device }
            }
        } catch (_: Exception) {}
        return device.ifEmpty { "téléphone" }
    }

    /** Last 4 chars of id_short (or encryption_pk as fallback), sanitized. */
    private fun shortIdSuffix(idShort: String, encPk: String): String {
        val src = idShort.ifEmpty { encPk }
        val alnum = src.filter { it.isLetterOrDigit() }
        return if (alnum.length >= 4) alnum.takeLast(4) else alnum.ifEmpty { "????" }
    }

    /** Logical parent of each Screen — the destination for hardware back and backLink. */
    private fun parentOf(s: Screen): Screen = when (s) {
        Screen.HOME            -> Screen.HOME
        Screen.RECEIVE         -> Screen.HOME
        Screen.READ            -> Screen.HOME
        Screen.SIGN            -> Screen.READ
        Screen.SEND_DOC        -> Screen.SESAME_PROFILE
        Screen.SESAME_PROFILE  -> Screen.CONTACTS
        Screen.CONTACTS        -> Screen.HOME
        Screen.INVITE          -> Screen.HOME
        Screen.MY_ID           -> Screen.HOME
    }

    @Deprecated("Use onBackPressedDispatcher")
    override fun onBackPressed() {
        when {
            onOnboarding -> Unit  // hardware back disabled during onboarding
            onManifesto -> {
                // From Mon identité → back returns to MY_ID. First-launch → back is a no-op
                // (user must tap [ Entrer ] to finish the manifesto).
                if (manifestoFromMyId) {
                    prefs().edit().putBoolean("manifeste_shown", true).apply()
                    onManifesto = false
                    manifestoPager = null
                    showScreen(Screen.MY_ID)
                }
            }
            onQrFullscreen -> {
                window?.attributes = window?.attributes?.apply { screenBrightness = -1f }
                showScreen(Screen.MY_ID)
            }
            currentScreen == Screen.HOME -> super.onBackPressed()
            else -> showScreen(parentOf(currentScreen))
        }
    }
}
