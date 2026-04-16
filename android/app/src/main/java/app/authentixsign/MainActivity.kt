package app.authentixsign

import android.content.Intent
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.DashPathEffect
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.FragmentActivity

class MainActivity : FragmentActivity() {

    private enum class Screen { HOME, RECEIVE, SIGN, SEND, CONTACTS }

    // ── Design tokens ───────────────────────────────────────────────────
    private val BG       = Color.parseColor("#f5f4f0")
    private val FG       = Color.parseColor("#1a1a18")
    private val FG2      = Color.parseColor("#3a3a36")
    private val FG3      = Color.parseColor("#6a6860")
    private val FG4      = Color.parseColor("#aaa89e")
    private val PURPLE   = Color.parseColor("#6655c0")
    private val PURPLE_L = Color.parseColor("#f0eefb")
    private val PURPLE_I = Color.parseColor("#ede9fb")   // intense bio
    private val GOLD     = Color.parseColor("#9a7a28")
    private val GOLD_L   = Color.parseColor("#f5eedc")
    private val GREEN    = Color.parseColor("#2d7a2d")
    private val GREEN_L  = Color.parseColor("#edf7ed")
    private val RED      = Color.parseColor("#b83232")
    private val BORDER   = Color.parseColor("#14000000") // ~8% black

    private val SERIF    = Typeface.create("serif", Typeface.NORMAL)
    private val SERIF_B  = Typeface.create("serif", Typeface.BOLD)
    private val MONO     = Typeface.MONOSPACE
    private val MONO_B   = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)

    private lateinit var container: FrameLayout
    private var currentScreen = Screen.HOME
    private var isSetupDone = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        container = FrameLayout(this).apply {
            setBackgroundColor(BG)
            layoutParams = FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
        }
        setContentView(container)

        val prefs = getSharedPreferences("authentix", MODE_PRIVATE)
        isSetupDone = prefs.contains("signing_pk")

        if (!isSetupDone) {
            showSetupScreen()
        } else {
            showScreen(Screen.HOME)
        }

        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        intent ?: return
        val uri = intent.data ?: return
        val path = uri.path ?: return
        when {
            path.endsWith(".authentix") -> showScreen(Screen.RECEIVE)
            path.endsWith(".authentix-id") -> showScreen(Screen.CONTACTS)
        }
    }

    // ── SETUP (first launch) ────────────────────────────────────────────

    private fun showSetupScreen() {
        container.removeAllViews()

        val layout = screenLayout()
        layout.addView(accentBar(GOLD))
        layout.addView(spacer(32))
        layout.addView(eyebrow("Premier lancement"))
        layout.addView(titleSerif("Créez\nvotre identité", GOLD))
        layout.addView(bodyMono("Posez votre empreinte pour générer vos clés cryptographiques. Elles ne quitteront jamais cet appareil."))
        layout.addView(spacer(24))

        val statusText = bodyMono("")
        layout.addView(statusText)
        layout.addView(spacer(16))

        layout.addView(bioZone(GOLD_L, goldBorderColor(), GOLD, "Poser l'empreinte") {
            statusText.text = "Authentification…"
            statusText.setTextColor(FG3)
            runBiometricSetup(statusText)
        })

        container.addView(wrapScroll(layout))
    }

    private fun runBiometricSetup(statusText: TextView) {
        BiometricHelper.authenticate(
            activity = this,
            title = "Créer votre identité",
            subtitle = "Posez votre doigt",
            onSuccess = { bioKeyBytes ->
                statusText.text = "Génération des clés…"
                performSetup(bioKeyBytes, statusText)
            },
            onError = { msg ->
                statusText.text = "Erreur : $msg"
                statusText.setTextColor(RED)
            }
        )
    }

    private fun performSetup(bioKeyBytes: ByteArray, statusText: TextView) {
        try {
            val androidId = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID) ?: "unknown"
            val result = AuthentixCore.setup(
                androidId = androidId,
                buildFingerprint = Build.FINGERPRINT,
                manufacturer = Build.MANUFACTURER,
                model = Build.MODEL,
                keystoreAttestation = ByteArray(0),
                bioKeyBytes = bioKeyBytes,
                osVersion = Build.VERSION.RELEASE,
                appVersion = "1.0.0",
            )

            val json = org.json.JSONObject(result)
            val kit = json.getJSONObject("kit")
            val prefs = getSharedPreferences("authentix", MODE_PRIVATE).edit()
            prefs.putString("signing_pk", kit.getString("signing_pk"))
            prefs.putString("encryption_pk", kit.getString("encryption_pk"))
            prefs.putString("markers", kit.getJSONObject("markers").toString())
            prefs.putString("signing_sk", json.getString("signing_sk"))
            prefs.putString("encryption_sk", json.getString("encryption_sk"))
            prefs.putString("master_seed", json.getString("master_seed"))
            prefs.putString("bio_hash", json.getString("bio_hash"))
            prefs.apply()

            isSetupDone = true
            statusText.text = "Identité créée"
            statusText.setTextColor(GREEN)

            container.postDelayed({ showScreen(Screen.HOME) }, 1200)
        } catch (e: Exception) {
            statusText.text = "Erreur : ${e.message}"
            statusText.setTextColor(RED)
        }
    }

    // ── NAVIGATION ──────────────────────────────────────────────────────

    private fun showScreen(screen: Screen) {
        currentScreen = screen
        container.removeAllViews()
        val layout = when (screen) {
            Screen.HOME     -> buildHomeScreen()
            Screen.RECEIVE  -> buildReceiveScreen()
            Screen.SIGN     -> buildSignScreen()
            Screen.SEND     -> buildSendScreen()
            Screen.CONTACTS -> buildContactsScreen()
        }
        container.addView(wrapScroll(layout))
    }

    // ── 1. HOME ─────────────────────────────────────────────────────────

    private fun buildHomeScreen(): LinearLayout {
        val layout = screenLayout()

        layout.addView(accentBar(PURPLE))

        // Top bar
        val top = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(18), dp(14), dp(18), dp(10))
        }
        top.addView(TextView(this).apply {
            text = "Authentix Sign"
            typeface = SERIF_B
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setTextColor(PURPLE)
            layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
        })
        top.addView(badge("v1.0", PURPLE_L, PURPLE))
        layout.addView(top)

        // Body
        val body = bodyPadding()

        body.addView(eyebrow("Prêt à signer"))
        body.addView(titleSerif("Documents", PURPLE))
        body.addView(spacer(14))

        // Empty state
        body.addView(cardWhite().apply {
            addView(TextView(this@MainActivity).apply {
                text = "Aucun document en attente"
                typeface = MONO
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
                setTextColor(FG4)
                gravity = Gravity.CENTER
                setPadding(dp(16), dp(24), dp(16), dp(24))
            })
        })
        body.addView(spacer(14))

        body.addView(bodyMono("Scannez un QR, ouvrez un fichier .authentix ou recevez un document par email."))
        body.addView(spacer(24))

        body.addView(ctaButton("Envoyer un document", PURPLE) { showScreen(Screen.SEND) })
        body.addView(spacer(8))
        body.addView(ctaButton("Contacts", Color.TRANSPARENT, FG3, true) { showScreen(Screen.CONTACTS) })

        layout.addView(body)
        layout.addView(progressDots(1, 5, PURPLE))
        return layout
    }

    // ── 2. RECEIVE ──────────────────────────────────────────────────────

    private fun buildReceiveScreen(): LinearLayout {
        val layout = screenLayout()

        layout.addView(accentBar(PURPLE))
        val top = topBar("Authentix Sign", PURPLE, "Étape 1/3")
        layout.addView(top)

        val body = bodyPadding()
        body.addView(eyebrow("Autorisation de réception"))
        body.addView(titleSerif("Confirmez\nla réception", PURPLE))
        body.addView(bodyMono("Posez votre empreinte pour confirmer que vous recevez ce document volontairement."))
        body.addView(spacer(14))

        // Bio zone — doux (purple light)
        body.addView(bioZone(PURPLE_L, purpleBorderColor(), PURPLE, "Poser l'empreinte") {
            BiometricHelper.authenticate(
                activity = this,
                title = "Réception du document",
                subtitle = "Confirmez votre identité",
                onSuccess = {
                    Toast.makeText(this, "Déchiffrement réussi", Toast.LENGTH_SHORT).show()
                },
                onError = { msg ->
                    Toast.makeText(this, "Erreur : $msg", Toast.LENGTH_SHORT).show()
                }
            )
        })
        body.addView(spacer(14))

        // Doc preview placeholder
        body.addView(docPreview())

        layout.addView(body)
        layout.addView(progressDots(2, 5, PURPLE))
        return layout
    }

    // ── 3. SIGN ─────────────────────────────────────────────────────────

    private fun buildSignScreen(): LinearLayout {
        val layout = screenLayout()

        layout.addView(accentBar(PURPLE))
        val top = topBar("Authentix Sign", PURPLE, "Étape 3/3")
        layout.addView(top)

        val body = bodyPadding()
        body.addView(eyebrow("Signature définitive"))
        body.addView(titleSerif("Signez\nmaintenant", PURPLE))
        body.addView(bodyMono("Cette empreinte sera fusionnée de façon irréversible avec le document et vos identifiants matériels."))
        body.addView(spacer(14))

        // Bio zone — intense (darker purple)
        body.addView(bioZone(PURPLE_I, purpleBorderIntense(), PURPLE, "Maintenir l'empreinte") {
            BiometricHelper.authenticate(
                activity = this,
                title = "Signature définitive",
                subtitle = "Maintenez votre empreinte",
                onSuccess = {
                    showSuccessScreen()
                },
                onError = { msg ->
                    Toast.makeText(this, "Erreur : $msg", Toast.LENGTH_SHORT).show()
                }
            )
        })
        body.addView(spacer(10))

        // Hash display
        body.addView(TextView(this).apply {
            text = "G_sig = SHA3-256( TAG ‖ H(doc) ‖ H(IDs) ‖ H(bio) ‖ τ )"
            typeface = MONO
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 8f)
            setTextColor(FG4)
            setLineSpacing(0f, 1.5f)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
                bottomMargin = dp(12)
            }
        })

        body.addView(ctaButton("Refuser de signer", Color.TRANSPARENT, FG3, true) {
            showScreen(Screen.HOME)
        })

        layout.addView(body)
        layout.addView(progressDots(4, 5, PURPLE))
        return layout
    }

    // ── SUCCESS (after sign) ────────────────────────────────────────────

    private fun showSuccessScreen() {
        container.removeAllViews()
        val layout = screenLayout()

        layout.addView(accentBar(PURPLE))
        val top = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(18), dp(14), dp(18), dp(10))
        }
        top.addView(TextView(this).apply {
            text = "Authentix Sign"
            typeface = SERIF_B
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setTextColor(PURPLE)
            layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
        })
        top.addView(badge("Signé", GREEN_L, GREEN))
        layout.addView(top)

        val body = bodyPadding()

        // Success icon
        body.addView(spacer(16))
        val checkCircle = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(dp(36), dp(36)).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                bottomMargin = dp(8)
            }
            background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setStroke(dp(2), GREEN)
                setColor(Color.TRANSPARENT)
            }
        }
        body.addView(checkCircle)

        body.addView(TextView(this).apply {
            text = "Document signé"
            typeface = SERIF_B
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f)
            setTextColor(GREEN)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        })
        body.addView(TextView(this).apply {
            text = "Calcul local · aucun serveur · hors ligne"
            typeface = MONO
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f)
            setTextColor(FG4)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
                topMargin = dp(4)
                bottomMargin = dp(16)
            }
        })

        // Certificate card
        body.addView(certCard())
        body.addView(spacer(14))

        body.addView(ctaButton("Envoyer le certificat", PURPLE) {
            Toast.makeText(this, "Envoi attestation — à implémenter", Toast.LENGTH_SHORT).show()
        })
        body.addView(spacer(8))
        body.addView(ctaButton("Enregistrer localement", Color.TRANSPARENT, FG3, true) {
            Toast.makeText(this, "Enregistrement local — à implémenter", Toast.LENGTH_SHORT).show()
        })

        layout.addView(body)
        layout.addView(progressDots(5, 5, PURPLE))
        container.addView(wrapScroll(layout))
    }

    // ── 4. SEND ─────────────────────────────────────────────────────────

    private fun buildSendScreen(): LinearLayout {
        val layout = screenLayout()

        layout.addView(accentBar(PURPLE))
        val top = topBar("Authentix Sign", PURPLE, "Envoi")
        layout.addView(top)

        val body = bodyPadding()
        body.addView(backLink { showScreen(Screen.HOME) })
        body.addView(eyebrow("Nouveau document"))
        body.addView(titleSerif("Envoyer", PURPLE))
        body.addView(bodyMono("Sélectionnez un PDF et un destinataire. Le document sera chiffré pour son appareil uniquement."))
        body.addView(spacer(18))

        // PDF selection
        body.addView(cardWhite().apply {
            addView(TextView(this@MainActivity).apply {
                text = "Sélectionnez un fichier PDF"
                typeface = MONO
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
                setTextColor(FG4)
                gravity = Gravity.CENTER
                setPadding(dp(16), dp(20), dp(16), dp(20))
            })
        })
        body.addView(spacer(10))

        // Recipient
        body.addView(cardWhite().apply {
            addView(TextView(this@MainActivity).apply {
                text = "Choisir un destinataire"
                typeface = MONO
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
                setTextColor(FG4)
                gravity = Gravity.CENTER
                setPadding(dp(16), dp(20), dp(16), dp(20))
            })
        })
        body.addView(spacer(18))

        body.addView(ctaButton("Chiffrer et envoyer", PURPLE) {
            Toast.makeText(this, "Chiffrement + envoi — à implémenter", Toast.LENGTH_SHORT).show()
        })
        body.addView(spacer(8))
        body.addView(ctaButton("Envoyer par email", Color.TRANSPARENT, FG3, true) {
            Toast.makeText(this, "Mode email — à implémenter", Toast.LENGTH_SHORT).show()
        })

        layout.addView(body)
        return layout
    }

    // ── 5. CONTACTS ─────────────────────────────────────────────────────

    private fun buildContactsScreen(): LinearLayout {
        val layout = screenLayout()

        layout.addView(accentBar(PURPLE))
        val top = topBar("Authentix Sign", PURPLE, "Contacts")
        layout.addView(top)

        val body = bodyPadding()
        body.addView(backLink { showScreen(Screen.HOME) })
        body.addView(eyebrow("Carnet"))
        body.addView(titleSerif("Contacts", PURPLE))
        body.addView(bodyMono("Vos contacts vérifient cryptographiquement leur identité via leur clé publique."))
        body.addView(spacer(18))

        // Empty state
        body.addView(cardWhite().apply {
            addView(TextView(this@MainActivity).apply {
                text = "Aucun contact"
                typeface = MONO
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
                setTextColor(FG4)
                gravity = Gravity.CENTER
                setPadding(dp(16), dp(24), dp(16), dp(24))
            })
        })
        body.addView(spacer(18))

        body.addView(ctaButton("Scanner un QR code", PURPLE) {
            Toast.makeText(this, "Scanner QR — à implémenter", Toast.LENGTH_SHORT).show()
        })
        body.addView(spacer(8))
        body.addView(ctaButton("Ouvrir un .authentix-id", Color.TRANSPARENT, FG3, true) {
            Toast.makeText(this, "Import kit — à implémenter", Toast.LENGTH_SHORT).show()
        })
        body.addView(spacer(24))

        // My keys
        body.addView(eyebrow("Mon identité"))
        body.addView(spacer(8))

        val prefs = getSharedPreferences("authentix", MODE_PRIVATE)
        val spk = prefs.getString("signing_pk", "—") ?: "—"
        val epk = prefs.getString("encryption_pk", "—") ?: "—"

        body.addView(certRow("Clé signature", truncateKey(spk)))
        body.addView(certRow("Clé chiffrement", truncateKey(epk)))

        layout.addView(body)
        return layout
    }

    // ── REUSABLE COMPONENTS ─────────────────────────────────────────────

    private fun dp(n: Int): Int = (n * resources.displayMetrics.density).toInt()

    private fun screenLayout(): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(BG)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }
    }

    private fun bodyPadding(): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(0), dp(18), dp(14))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }
    }

    private fun wrapScroll(child: View): ScrollView {
        return ScrollView(this).apply {
            setBackgroundColor(BG)
            layoutParams = FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
            addView(child)
        }
    }

    private fun accentBar(color: Int): View {
        return View(this).apply {
            setBackgroundColor(color)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, dp(3))
        }
    }

    private fun topBar(product: String, productColor: Int, step: String): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(18), dp(14), dp(18), dp(10))
            addView(TextView(this@MainActivity).apply {
                text = product
                typeface = SERIF_B
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
                setTextColor(productColor)
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
            })
            addView(TextView(this@MainActivity).apply {
                text = step.uppercase()
                typeface = MONO
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f)
                setTextColor(FG4)
                letterSpacing = 0.1f
            })
        }
    }

    private fun eyebrow(text: String): TextView {
        return TextView(this).apply {
            this.text = text.uppercase()
            typeface = MONO
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f)
            setTextColor(FG4)
            letterSpacing = 0.16f
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
                bottomMargin = dp(6)
            }
        }
    }

    private fun titleSerif(text: String, color: Int): TextView {
        return TextView(this).apply {
            this.text = text
            typeface = SERIF_B
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
            setTextColor(color)
            setLineSpacing(0f, 1.1f)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
                bottomMargin = dp(10)
            }
        }
    }

    private fun bodyMono(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            typeface = MONO
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
            setTextColor(FG3)
            setLineSpacing(0f, 1.6f)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
                bottomMargin = dp(14)
            }
        }
    }

    private fun spacer(heightDp: Int): View {
        return View(this).apply {
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, dp(heightDp))
        }
    }

    private fun ctaButton(label: String, bgColor: Int, textColor: Int = Color.WHITE, outline: Boolean = false, onClick: () -> Unit): Button {
        return Button(this).apply {
            text = label.uppercase()
            typeface = MONO
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
            setTextColor(textColor)
            letterSpacing = 0.1f
            isAllCaps = false
            setPadding(dp(12), dp(12), dp(12), dp(12))
            stateListAnimator = null
            elevation = 0f
            if (outline) {
                setBackgroundColor(Color.TRANSPARENT)
                background = GradientDrawable().apply {
                    setColor(Color.TRANSPARENT)
                    setStroke(dp(1), BORDER)
                }
            } else {
                setBackgroundColor(bgColor)
            }
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
            setOnClickListener { onClick() }
        }
    }

    private fun badge(text: String, bgColor: Int, textColor: Int): TextView {
        return TextView(this).apply {
            this.text = text
            typeface = MONO
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
            setTextColor(textColor)
            letterSpacing = 0.08f
            setPadding(dp(10), dp(4), dp(10), dp(4))
            background = GradientDrawable().apply {
                setColor(bgColor)
                cornerRadius = dp(2).toFloat()
            }
        }
    }

    private fun backLink(onClick: () -> Unit): TextView {
        return TextView(this).apply {
            text = "← Retour"
            typeface = MONO
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            setTextColor(PURPLE)
            setPadding(0, 0, 0, dp(14))
            setOnClickListener { onClick() }
            layoutParams = LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT)
        }
    }

    private fun bioZone(
        bgColor: Int,
        borderColor: Int,
        accentColor: Int,
        label: String,
        onClick: () -> Unit,
    ): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dp(20), dp(20), dp(20), dp(20))
            background = GradientDrawable().apply {
                setColor(bgColor)
                setStroke(dp(1), borderColor)
                cornerRadius = dp(6).toFloat()
            }
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
                bottomMargin = dp(14)
            }

            // Fingerprint icon placeholder
            addView(View(this@MainActivity).apply {
                layoutParams = LinearLayout.LayoutParams(dp(40), dp(40)).apply {
                    bottomMargin = dp(8)
                }
                setBackgroundColor(Color.TRANSPARENT)
            })

            addView(TextView(this@MainActivity).apply {
                text = label.uppercase()
                typeface = MONO
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f)
                setTextColor(accentColor)
                letterSpacing = 0.1f
            })

            setOnClickListener { onClick() }
        }
    }

    private fun docPreview(): LinearLayout {
        return cardWhite().apply {
            setPadding(dp(12), dp(12), dp(12), dp(12))
            for (i in 0 until 6) {
                val width = when {
                    i == 2 || i == 5 -> 0.6f
                    i == 4 -> 0.4f
                    else -> 1.0f
                }
                addView(View(this@MainActivity).apply {
                    setBackgroundColor(Color.parseColor("#0f000000"))
                    layoutParams = LinearLayout.LayoutParams(
                        if (width < 1f) (resources.displayMetrics.widthPixels * width * 0.7f).toInt() else MATCH_PARENT,
                        dp(6)
                    ).apply {
                        bottomMargin = dp(5)
                    }
                    background = GradientDrawable().apply {
                        setColor(Color.parseColor("#0f000000"))
                        cornerRadius = dp(2).toFloat()
                    }
                })
            }
        }
    }

    private fun cardWhite(): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = GradientDrawable().apply {
                setColor(Color.WHITE)
                setStroke(1, BORDER)
                cornerRadius = dp(4).toFloat()
            }
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
                bottomMargin = dp(0)
            }
        }
    }

    private fun certCard(): LinearLayout {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), dp(12), dp(12), dp(12))
            background = GradientDrawable().apply {
                setColor(PURPLE_L)
                setStroke(dp(1), purpleBorderColor())
                cornerRadius = dp(4).toFloat()
            }
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }
        card.addView(certRow("Signataire", "Vous"))
        card.addView(certRow("Dispositif", "${Build.MANUFACTURER} ${Build.MODEL}"))
        card.addView(certRow("Horodatage τ", "—"))
        card.addView(certRow("H(doc)", "—"))
        card.addView(certRow("Taille cert.", "— · autonome"))
        return card
    }

    private fun certRow(label: String, value: String): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
                bottomMargin = dp(5)
            }
            addView(TextView(this@MainActivity).apply {
                text = label
                typeface = MONO
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f)
                setTextColor(FG4)
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
            })
            addView(TextView(this@MainActivity).apply {
                text = value
                typeface = MONO
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f)
                setTextColor(PURPLE)
            })
        }
    }

    private fun progressDots(active: Int, total: Int, color: Int): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            setPadding(0, dp(10), 0, dp(14))
            for (i in 1..total) {
                addView(View(this@MainActivity).apply {
                    val bg = GradientDrawable().apply {
                        shape = GradientDrawable.OVAL
                        setColor(if (i <= active) color else BORDER)
                    }
                    background = bg
                    layoutParams = LinearLayout.LayoutParams(dp(6), dp(6)).apply {
                        setMargins(dp(2), 0, dp(2), 0)
                    }
                })
            }
        }
    }

    private fun purpleBorderColor(): Int = Color.argb(46, 102, 85, 192)   // ~18%
    private fun purpleBorderIntense(): Int = Color.argb(77, 102, 85, 192) // ~30%
    private fun goldBorderColor(): Int = Color.argb(46, 154, 122, 40)     // ~18%

    private fun truncateKey(b64: String): String {
        return if (b64.length > 12) "${b64.take(6)}…${b64.takeLast(4)}" else b64
    }

    @Deprecated("Use onBackPressedDispatcher")
    override fun onBackPressed() {
        if (currentScreen != Screen.HOME) showScreen(Screen.HOME)
        else super.onBackPressed()
    }
}
