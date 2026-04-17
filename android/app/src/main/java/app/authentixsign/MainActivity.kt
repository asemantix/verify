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

    private enum class Screen { HOME, RECEIVE, READ, SIGN, SEND, CONTACTS, MY_ID }
    private enum class SetupReason { FIRST_TIME, INVALIDATED, LEGACY_RESET }
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

    private val SERIF_B  = Typeface.create("serif", Typeface.BOLD)
    private val MONO     = Typeface.MONOSPACE

    private lateinit var container: FrameLayout
    private var currentScreen = Screen.HOME
    private var isSetupDone = false

    // ── Document flow state ──────────────────────────────────────────────
    private var pendingPayloadJson: String? = null
    private var pendingDocRef: String = ""
    private var pendingDocSubject: String = ""
    private var pendingSenderName: String = ""
    private var pendingSenderPk: String = ""
    private var decryptedPdfBytes: ByteArray? = null
    private var lastAttestationJson: String? = null

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
                Toast.makeText(this, "✅ Contact ajouté : $name — $device", Toast.LENGTH_LONG).show()
            } else {
                Toast.makeText(this, "❌ Clé Sésame non vérifiée — fichier corrompu ou falsifié", Toast.LENGTH_LONG).show()
            }
            showScreen(Screen.CONTACTS)
        } catch (e: Exception) {
            Toast.makeText(this, "Erreur import : ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private val pickPdfLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@registerForActivityResult
        try {
            selectedPdfBytes = contentResolver.openInputStream(uri)?.readBytes()
            selectedPdfName = uri.lastPathSegment ?: "document.pdf"
            Toast.makeText(this, "PDF sélectionné : ${selectedPdfBytes!!.size} octets", Toast.LENGTH_SHORT).show()
            showScreen(Screen.SEND)
        } catch (e: Exception) {
            Toast.makeText(this, "Erreur : ${e.message}", Toast.LENGTH_LONG).show()
        }
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
            showScreen(Screen.CONTACTS)
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
                if (!isSetupDone) showSetupScreen() else showScreen(Screen.HOME)
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
                showScreen(Screen.CONTACTS)
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
            startActivity(Intent.createChooser(intent, "Notifier mes contacts"))
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
            SetupReason.FIRST_TIME -> {
                body.addView(eyebrow("Premier lancement"))
                body.addView(titleSerif("Créez votre\nidentité", GOLD))
                body.addView(sub("Posez votre empreinte pour générer vos clés cryptographiques. Elles ne quitteront jamais cet appareil."))
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
                }.apply()
                isSetupDone = true
                status.text = "Identité créée ✓"; status.setTextColor(GREEN)
                val reasonForSuccess = setupReason
                setupReason = SetupReason.FIRST_TIME
                container.postDelayed({
                    if (reasonForSuccess == SetupReason.FIRST_TIME) showScreen(Screen.HOME)
                    else showPostSetupSuccess()
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
        body.addView(sub("Vos contacts doivent mettre à jour votre clé Sésame pour pouvoir vous envoyer des documents."))
        body.addView(spacer(12))
        body.addView(guideText("Le bouton ci-dessous ouvre votre application mail avec votre nouvelle clé en pièce jointe. Choisissez vos destinataires dans le carnet d'adresses de votre mail."))
        body.addView(spacer(14))

        body.addView(cta("Notifier tous mes contacts", GOLD) { notifyAllContacts() })
        body.addView(spacer(8))
        body.addView(ctaOutline("Plus tard") { showScreen(Screen.HOME) })

        root.addView(body)
        container.addView(scroll(root))
    }

    // ════════════════════════════════════════════════════════════════════
    //  NAVIGATION
    // ════════════════════════════════════════════════════════════════════

    private fun showScreen(s: Screen) {
        currentScreen = s; container.removeAllViews()
        container.addView(scroll(when (s) {
            Screen.HOME     -> buildHome()
            Screen.RECEIVE  -> buildReceive()
            Screen.READ     -> buildRead()
            Screen.SIGN     -> buildSign()
            Screen.SEND     -> buildSend()
            Screen.CONTACTS -> buildContacts()
            Screen.MY_ID    -> buildMyId()
        }))
    }

    // ════════════════════════════════════════════════════════════════════
    //  1. HOME — Accueil / Scanner QR
    // ════════════════════════════════════════════════════════════════════

    private fun buildHome(): LinearLayout {
        val root = screenRoot()
        root.addView(accentBar(PURPLE))
        root.addView(topBar("Sésame", PURPLE, badge("v1.0", PURPLE_L, PURPLE)))

        val body = bodyPad()
        body.addView(eyebrow("Prêt à signer"))
        body.addView(titleSerif("Accueil", PURPLE))
        body.addView(sub("Sésame vous permet de recevoir, lire et signer des documents de façon sécurisée — tout se passe sur votre téléphone, sans serveur."))
        body.addView(spacer(6))
        body.addView(guideText("Scannez un QR code pour ouvrir un document, ou utilisez les boutons ci-dessous pour envoyer, gérer vos contacts ou partager votre identité."))
        body.addView(spacer(14))

        // QR zone
        body.addView(qrZone())
        body.addView(spacer(14))

        body.addView(cta("Ouvrir l'appareil photo", PURPLE) {
            launchQrScanner()
        })
        body.addView(spacer(8))
        body.addView(ctaOutline("Envoyer un document") { showScreen(Screen.SEND) })
        body.addView(spacer(8))
        body.addView(ctaOutline("Contacts") { showScreen(Screen.CONTACTS) })
        body.addView(spacer(8))
        body.addView(cta("Mon identité / Mon QR", GOLD) { showScreen(Screen.MY_ID) })

        root.addView(body)
        root.addView(dots(1, 5, PURPLE))
        return root
    }

    // ════════════════════════════════════════════════════════════════════
    //  2. RECEIVE — Biométrie réception (ton doux)
    // ════════════════════════════════════════════════════════════════════

    private fun buildReceive(): LinearLayout {
        val root = screenRoot()
        root.addView(accentBar(PURPLE))
        root.addView(topBar("Sésame", PURPLE, stepLabel("Étape 1/3")))

        val body = bodyPad()
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
        val root = screenRoot()
        root.addView(accentBar(PURPLE))
        root.addView(topBar("Sésame", PURPLE, stepLabel("Étape 2/3")))

        val body = bodyPad()
        body.addView(eyebrow("Lecture obligatoire"))
        body.addView(titleSerif("Lisez le\ndocument", PURPLE))
        body.addView(guideText("Prenez le temps de lire le document ci-dessous. Le bouton de signature s'activera après 10 secondes de lecture."))
        body.addView(spacer(10))

        // Document info card
        val pdf = decryptedPdfBytes
        if (pdf != null) {
            val hashHex = sha3Hex(pdf)
            val infoCard = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL; setPadding(dp(12), dp(12), dp(12), dp(12))
                background = GradientDrawable().apply { setColor(GREEN_L); setStroke(dp(1), Color.argb(46, 45, 122, 45)); cornerRadius = dp(4).toFloat() }
                layoutParams = lp().apply { bottomMargin = dp(10) }
            }
            infoCard.addView(certRow("État", "Déchiffré ✓", GREEN))
            infoCard.addView(certRow("Taille", "${pdf.size} octets", GREEN))
            infoCard.addView(certRow("H(doc)", "${hashHex.take(8)}…${hashHex.takeLast(4)}", GREEN))
            infoCard.addView(certRow("Référence", pendingDocRef, GREEN))
            body.addView(infoCard)

            // Render first page with PdfRenderer if possible
            val pdfBitmap = renderPdfFirstPage(pdf)
            if (pdfBitmap != null) {
                val iv = android.widget.ImageView(this).apply {
                    setImageBitmap(pdfBitmap)
                    scaleType = android.widget.ImageView.ScaleType.FIT_CENTER
                    adjustViewBounds = true
                    setPadding(dp(2), dp(2), dp(2), dp(2))
                    background = card_bg()
                    layoutParams = lp().apply { bottomMargin = dp(14) }
                }
                body.addView(iv)
            } else {
                body.addView(docPreview(10))
            }
        } else {
            body.addView(docPreview(10))
        }
        body.addView(spacer(6))

        // Timer bar
        val timerRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            layoutParams = lp().apply { bottomMargin = dp(14) }
        }
        val timerTxt = timerLabel("0:10")
        val timerElapsed = timerLabel("0:00")
        val timerBarBg = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, dp(3), 1f).apply { setMargins(dp(10), 0, dp(10), 0) }
            background = GradientDrawable().apply { setColor(Color.argb(38, 102, 85, 192)); cornerRadius = dp(2).toFloat() }
        }
        timerRow.addView(timerElapsed); timerRow.addView(timerBarBg); timerRow.addView(timerTxt)
        body.addView(timerRow)

        body.addView(sub("Lecture obligatoire — le bouton s'active dans 10 secondes").apply { gravity = Gravity.CENTER; setTextColor(FG4) })
        body.addView(spacer(14))

        val signBtn = cta("Signer ce document", PURPLE) { showScreen(Screen.SIGN) }
        signBtn.alpha = 0.4f; signBtn.isEnabled = false
        body.addView(signBtn)

        // Countdown — enable button after 10s
        object : CountDownTimer(10000, 1000) {
            var elapsed = 0
            override fun onTick(ms: Long) { elapsed++; timerElapsed.text = "0:%02d".format(elapsed); signBtn.alpha = 0.4f + (elapsed / 10f) * 0.6f }
            override fun onFinish() { timerElapsed.text = "0:10"; signBtn.alpha = 1f; signBtn.isEnabled = true }
        }.start()

        root.addView(body)
        root.addView(dots(3, 5, PURPLE))
        return root
    }

    // ════════════════════════════════════════════════════════════════════
    //  4. SIGN — Biométrie signature (ton intense)
    // ════════════════════════════════════════════════════════════════════

    private fun buildSign(): LinearLayout {
        val root = screenRoot()
        root.addView(accentBar(PURPLE))
        root.addView(topBar("Sésame", PURPLE, stepLabel("Étape 3/3")))

        val body = bodyPad()
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

    private fun buildSend(): LinearLayout {
        val root = screenRoot()
        root.addView(accentBar(PURPLE))
        root.addView(topBar("Sésame", PURPLE, stepLabel("Envoi")))

        val body = bodyPad()
        body.addView(backLink { showScreen(Screen.HOME) })
        body.addView(eyebrow("Nouveau document"))
        body.addView(titleSerif("Envoyer", PURPLE))
        body.addView(sub("Envoyez un document à signer de façon sécurisée."))
        body.addView(guideText("① Choisissez un fichier PDF\n② Sélectionnez le destinataire dans vos contacts\n③ Appuyez sur Envoyer — le document sera chiffré pour le téléphone du destinataire uniquement"))
        body.addView(spacer(18))

        // Pre-PDF explainer (écran 2b) — mono 11sp, FG3 (#6a6860)
        body.addView(monoNote(
            "Sélectionnez le fichier. Il ne sera envoyé qu'une fois chiffré — personne d'autre que votre destinataire ne pourra le lire. Il ne s'ouvrira pas sur sa boîte mail, pas sur son ordinateur, pas sur un autre téléphone. Uniquement sur son téléphone, avec son empreinte digitale."
        ))

        // PDF picker card — show selected state
        val pdfLabel = if (selectedPdfBytes != null) "✓ ${selectedPdfName} (${selectedPdfBytes!!.size} octets)" else "Sélectionnez un fichier PDF"
        body.addView(pickerCard("📄", pdfLabel, "Parcourir") {
            pickPdfLauncher.launch(arrayOf("application/pdf"))
        })
        body.addView(spacer(10))

        // Recipient card — show selected state
        val recipientLabel = if (selectedRecipient != null) "✓ ${selectedRecipient!!.optString("name", "?")} — ${selectedRecipient!!.optString("device", "")}" else "Choisir un destinataire"
        body.addView(pickerCard("👤", recipientLabel, "Contacts") {
            showScreen(Screen.CONTACTS)
        })
        body.addView(spacer(10))

        // Ref / subject
        body.addView(fieldCard("Référence", "Ex: VENTE-2026-042"))
        body.addView(spacer(10))
        body.addView(fieldCard("Objet", "Ex: Compromis de vente"))
        body.addView(spacer(24))

        val sendReady = selectedPdfBytes != null && selectedRecipient != null

        // Écran 2c — Confirmation with device markers (shown when both PDF + recipient are selected)
        if (sendReady) {
            val r = selectedRecipient!!
            val recipientName = r.optString("name", "Destinataire")
            val device = r.optString("device", "")
            val model = extractModel(device, r.optString("markers", "{}"))
            val short4 = shortIdSuffix(r.optString("id_short", ""), r.optString("encryption_pk", ""))
            body.addView(sesameInfoBlock(
                "Seul le $model ...$short4 de $recipientName peut ouvrir ce document. Même sur sa boîte mail, même sur un autre téléphone — illisible."
            ))
            body.addView(spacer(8))
        }

        val sendBtn = cta("Chiffrer et envoyer par email", PURPLE) {
            doEncryptAndSend()
        }
        if (!sendReady) { sendBtn.alpha = 0.4f; sendBtn.isEnabled = false }
        body.addView(sendBtn)

        if (!sendReady) {
            body.addView(spacer(8))
            body.addView(sub("Sélectionnez un PDF et un destinataire pour activer l'envoi.").apply { gravity = Gravity.CENTER; setTextColor(FG4) })
        }

        root.addView(body)
        return root
    }

    private fun doEncryptAndSend() {
        val pdf = selectedPdfBytes ?: return
        val recipient = selectedRecipient ?: return
        val recipientEncPk = recipient.getString("encryption_pk")
        val recipientName = recipient.optString("name", "Destinataire")

        val blobB64 = prefs().getString("signing_sk_blob", "") ?: ""
        val blob = android.util.Base64.decode(blobB64, android.util.Base64.DEFAULT)
        BiometricHelper.unwrapKey(this, "Signer et chiffrer", "Confirmez l'envoi avec votre empreinte", blob,
            onSuccess = { combined ->
                var sk: ByteArray? = null
                val bio = ByteArray(32).also { SecureRandom().nextBytes(it) }
                try {
                    val pair = org.json.JSONObject(String(combined, Charsets.UTF_8))
                    sk = android.util.Base64.decode(pair.getString("sign_sk"), android.util.Base64.DEFAULT)
                    val markersJson = prefs().getString("markers", "{}") ?: "{}"
                    val aid = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID) ?: ""
                    val deviceIds = (aid + Build.FINGERPRINT).toByteArray()
                    val tau = MonotonicCounter.next(this)
                    val myPk = prefs().getString("signing_pk", "") ?: ""
                    val docRef = "DOC-${System.currentTimeMillis()}"

                    val attJson = AuthentixCore.signDocument(sk, pdf, bio, deviceIds, tau, markersJson, docRef, myPk)
                    if (attJson.contains("\"error\"")) {
                        Toast.makeText(this, "Erreur signature : $attJson", Toast.LENGTH_LONG).show()
                        return@unwrapKey
                    }

                    val payloadJson = AuthentixCore.encryptFor(recipientEncPk, pdf)
                    if (payloadJson.contains("\"error\"")) {
                        Toast.makeText(this, "Erreur chiffrement : $payloadJson", Toast.LENGTH_LONG).show()
                        return@unwrapKey
                    }

                    val envelope = org.json.JSONObject().apply {
                        put("version", 2)
                        put("type", "document")
                        put("payload", org.json.JSONObject(payloadJson))
                        put("attestation", org.json.JSONObject(attJson))
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
                    val intent = Intent(Intent.ACTION_SEND).apply {
                        type = "application/x-sesame"
                        putExtra(Intent.EXTRA_STREAM, uri)
                        putExtra(Intent.EXTRA_SUBJECT, "Document Sésame — $docRef")
                        putExtra(Intent.EXTRA_TEXT, "Document chiffré envoyé via SÉSAME.\nSeul votre téléphone peut l'ouvrir.")
                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    }
                    startActivity(Intent.createChooser(intent, "Envoyer le document chiffré"))

                    selectedPdfBytes = null; selectedPdfName = ""; selectedRecipient = null
                    Toast.makeText(this, "✓ Document chiffré et envoyé (τ=$tau)", Toast.LENGTH_LONG).show()
                } catch (e: Exception) {
                    Toast.makeText(this, "Erreur : ${e.message}", Toast.LENGTH_LONG).show()
                } finally {
                    sk?.let { Arrays.fill(it, 0) }
                    Arrays.fill(bio, 0)
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

    private fun buildContacts(): LinearLayout {
        val root = screenRoot()
        root.addView(accentBar(PURPLE))
        root.addView(topBar("Sésame", PURPLE, stepLabel("Contacts")))

        val body = bodyPad()
        body.addView(backLink { showScreen(Screen.HOME) })
        body.addView(eyebrow("Carnet"))
        body.addView(titleSerif("Contacts", PURPLE))
        body.addView(sub("Vos contacts sont les personnes à qui vous pouvez envoyer des documents chiffrés."))
        body.addView(guideText("Pour ajouter un contact, scannez son QR code (en face à face) ou ouvrez le fichier .sesame-id qu'il vous a envoyé. Chaque contact est lié à un appareil précis."))
        body.addView(spacer(18))

        // Contact list
        val contacts = loadContacts()
        if (contacts.length() == 0) {
            val emptyCard = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER
                setPadding(dp(16), dp(32), dp(16), dp(32))
                background = card_bg()
                layoutParams = lp().apply { bottomMargin = dp(14) }
            }
            emptyCard.addView(TextView(this).apply {
                text = "Aucun contact"; typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f); setTextColor(FG4); gravity = Gravity.CENTER
            })
            emptyCard.addView(spacer(4))
            emptyCard.addView(TextView(this).apply {
                text = "Scannez un QR ou ouvrez un .sesame-id"; typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f); setTextColor(FG4); gravity = Gravity.CENTER
            })
            body.addView(emptyCard)
        } else {
            for (i in 0 until contacts.length()) {
                val c = contacts.getJSONObject(i)
                val isObsolete = c.optBoolean("obsolete", false)
                val contactCard = LinearLayout(this).apply {
                    orientation = LinearLayout.VERTICAL; setPadding(dp(12), dp(12), dp(12), dp(12))
                    background = GradientDrawable().apply {
                        setColor(if (isObsolete) Color.parseColor("#fff6e0") else PURPLE_L)
                        setStroke(dp(1), if (isObsolete) Color.parseColor("#b88a20") else purpleBorder())
                        cornerRadius = dp(4).toFloat()
                    }
                    layoutParams = lp().apply { bottomMargin = dp(8) }
                    isClickable = !isObsolete; isFocusable = !isObsolete
                    if (!isObsolete) setOnClickListener {
                        selectedRecipient = c
                        Toast.makeText(this@MainActivity, "Destinataire : ${c.getString("name")}", Toast.LENGTH_SHORT).show()
                        showScreen(Screen.SEND)
                    }
                }
                val headerLabel = if (isObsolete) "⚠️ ${c.getString("name")}" else "✅ ${c.getString("name")}"
                val headerColor = if (isObsolete) Color.parseColor("#b88a20") else PURPLE
                contactCard.addView(certRow(headerLabel, c.optString("device", "—"), headerColor))
                if (isObsolete) {
                    contactCard.addView(TextView(this).apply {
                        text = "Clé obsolète — demandez à ce contact de renvoyer son kit Sésame"
                        typeface = MONO; setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f)
                        setTextColor(Color.parseColor("#b88a20"))
                        layoutParams = lp().apply { topMargin = dp(4); bottomMargin = dp(4) }
                    })
                }
                contactCard.addView(certRow("ID", c.optString("id_short", "—"), headerColor))
                contactCard.addView(certRow("Clé Sésame", trunc(c.getString("encryption_pk")), headerColor))
                body.addView(contactCard)
            }
        }
        body.addView(spacer(10))

        // ⓘ Clé Sésame — explanatory block (écran 2a)
        body.addView(eyebrow("ⓘ Clé Sésame"))
        body.addView(spacer(6))
        body.addView(sesameInfoBlock(
            "C'est la fusion unique et inséparable de trois éléments : l'identité Sésame de votre destinataire, son téléphone physique, et son empreinte digitale. Les trois doivent être réunis pour ouvrir le document. Voler un seul élément ne suffit pas."
        ))
        body.addView(spacer(14))

        body.addView(cta("Scanner un QR code", PURPLE) {
            launchQrScanner()
        })
        body.addView(spacer(8))
        body.addView(ctaOutline("Ouvrir un .sesame-id") {
            importKitLauncher.launch(arrayOf("*/*"))
        })
        body.addView(spacer(32))

        // My identity section
        body.addView(eyebrow("Mon identité"))
        body.addView(spacer(10))

        val idCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(12), dp(12), dp(12), dp(12))
            background = GradientDrawable().apply { setColor(GOLD_L); setStroke(dp(1), goldBorder()); cornerRadius = dp(4).toFloat() }
            layoutParams = lp().apply { bottomMargin = dp(14) }
        }
        val pk = prefs().getString("signing_pk", "—") ?: "—"
        val epk = prefs().getString("encryption_pk", "—") ?: "—"
        idCard.addView(certRow("Appareil", "${Build.MANUFACTURER} ${Build.MODEL}", GOLD))
        idCard.addView(certRow("Clé signature", trunc(pk), GOLD))
        idCard.addView(certRow("Clé chiffrement", trunc(epk), GOLD))
        idCard.addView(certRow("Compteur τ", MonotonicCounter.peek(this).toString(), GOLD))
        body.addView(idCard)

        body.addView(cta("Partager mon QR code", GOLD) {
            showScreen(Screen.MY_ID)
        })

        root.addView(body)
        return root
    }

    // ════════════════════════════════════════════════════════════════════
    //  8. MY_ID — Mon identité / Mon QR
    // ════════════════════════════════════════════════════════════════════

    private fun buildMyId(): LinearLayout {
        val root = screenRoot()
        root.addView(accentBar(GOLD))
        root.addView(topBar("Sésame", GOLD, stepLabel("Mon identité")))

        val body = bodyPad()
        body.addView(backLink { showScreen(Screen.HOME) })
        body.addView(eyebrow("Carte d'identité numérique"))
        body.addView(titleSerif("Mon\nidentité", GOLD))
        body.addView(sub("Votre carte d'identité numérique. Partagez-la avec les personnes qui doivent vous envoyer des documents chiffrés."))
        body.addView(guideText("Comment partager :\n① Montrez le QR code ci-dessous à scanner (en face à face)\n② Envoyez-le par email avec le bouton « Partager »\n③ Exportez un fichier .sesame-id à transmettre"))
        body.addView(spacer(14))

        val spk = prefs().getString("signing_pk", "") ?: ""
        val epk = prefs().getString("encryption_pk", "") ?: ""

        // Kit was signed at setup time and cached — no bio prompt needed to display it.
        val kitJson = prefs().getString("signed_kit_json", "") ?: fallbackUnsignedKit(spk, epk)
        val qrBitmap = generateQr(kitJson)

        if (qrBitmap != null) {
            val qrContainer = LinearLayout(this).apply {
                gravity = Gravity.CENTER; setPadding(dp(16), dp(16), dp(16), dp(16))
                background = card_bg(); layoutParams = lp().apply { bottomMargin = dp(14) }
            }
            val iv = android.widget.ImageView(this).apply {
                setImageBitmap(qrBitmap); scaleType = android.widget.ImageView.ScaleType.FIT_CENTER
                layoutParams = LinearLayout.LayoutParams(dp(200), dp(200))
            }
            qrContainer.addView(iv)
            body.addView(qrContainer)
        } else {
            body.addView(sub("Erreur de génération du QR code").apply { setTextColor(RED) })
        }
        body.addView(spacer(14))

        // Identity card
        val idCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(12), dp(12), dp(12), dp(12))
            background = GradientDrawable().apply { setColor(GOLD_L); setStroke(dp(1), goldBorder()); cornerRadius = dp(4).toFloat() }
            layoutParams = lp().apply { bottomMargin = dp(14) }
        }
        idCard.addView(certRow("Appareil", "${Build.MANUFACTURER} ${Build.MODEL}", GOLD))
        idCard.addView(certRow("Clé signature", trunc(spk), GOLD))
        idCard.addView(certRow("Clé chiffrement", trunc(epk), GOLD))
        idCard.addView(certRow("Compteur τ", MonotonicCounter.peek(this).toString(), GOLD))
        body.addView(idCard)

        // Full keys (copyable)
        body.addView(eyebrow("Clés complètes (appui long = copier)"))
        body.addView(spacer(6))
        body.addView(copyableKey("signing_pk", spk))
        body.addView(spacer(4))
        body.addView(copyableKey("encryption_pk", epk))
        body.addView(spacer(24))

        // Share button
        body.addView(cta("Partager par email", GOLD) { shareKit(kitJson) })
        body.addView(spacer(8))
        body.addView(ctaOutline("Exporter .sesame-id") { exportKit(kitJson) })
        body.addView(spacer(8))
        body.addView(ctaOutline("Notifier mes contacts d'un changement") { notifyAllContacts() })

        root.addView(body)
        return root
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
        this.text = text; typeface = SERIF_B; setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f); setTextColor(color)
        setLineSpacing(0f, 1.1f); layoutParams = lp().apply { bottomMargin = dp(10) }
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

    @Deprecated("Use onBackPressedDispatcher")
    override fun onBackPressed() {
        when (currentScreen) {
            Screen.READ  -> showScreen(Screen.RECEIVE)
            Screen.SIGN  -> showScreen(Screen.READ)
            Screen.MY_ID -> showScreen(Screen.HOME)
            Screen.HOME  -> super.onBackPressed()
            else         -> showScreen(Screen.HOME)
        }
    }
}
