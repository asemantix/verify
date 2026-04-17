package app.authentixsign

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.view.animation.AlphaAnimation
import android.widget.LinearLayout
import android.widget.TextView

/**
 * 2-second splash shown before [MainActivity]. Declared as the launcher
 * activity in AndroidManifest — this is the first thing the user sees.
 */
class SplashActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val density = resources.displayMetrics.density
        fun dp(v: Int) = (v * density).toInt()

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setBackgroundColor(Color.parseColor("#f5f4f0"))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
        }

        val cormorantBold = androidx.core.content.res.ResourcesCompat.getFont(this, R.font.cormorant_garamond_bold)
            ?: Typeface.create("serif", Typeface.BOLD)
        val cormorantRegular = androidx.core.content.res.ResourcesCompat.getFont(this, R.font.cormorant_garamond_regular)
            ?: Typeface.create("serif", Typeface.NORMAL)
        val jetbrainsMono = androidx.core.content.res.ResourcesCompat.getFont(this, R.font.jetbrains_mono_regular)
            ?: Typeface.MONOSPACE

        // Spacer above — weight pushes content toward vertical middle/bottom layout.
        root.addView(View(this), LinearLayout.LayoutParams(MATCH_PARENT, 0, 1.2f))

        val title = TextView(this).apply {
            text = "SÉSAME"
            setTextColor(Color.parseColor("#6655c0"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 72f)
            typeface = cormorantBold
            gravity = Gravity.CENTER
        }
        root.addView(title, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        val slogan = TextView(this).apply {
            text = "Ouvre-toi !"
            setTextColor(Color.parseColor("#6a6860"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 32f)
            typeface = Typeface.create(cormorantRegular, Typeface.ITALIC)
            gravity = Gravity.CENTER
        }
        root.addView(slogan, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
            topMargin = dp(8)
        })

        // Flex spacer pushes the brand quote to the bottom.
        root.addView(View(this), LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))

        val quote = TextView(this).apply {
            text = "SÉSAME n'est pas une messagerie.\nC'est un cercle fermé de confiance documentaire."
            setTextColor(Color.parseColor("#aaa89e"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            typeface = jetbrainsMono
            gravity = Gravity.CENTER
            setLineSpacing(0f, 1.4f)
        }
        root.addView(quote, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
            setMargins(dp(24), 0, dp(24), dp(32))
        })

        setContentView(root)

        val fade = AlphaAnimation(0f, 1f).apply {
            duration = 900
            fillAfter = true
        }
        root.startAnimation(fade)

        Handler(Looper.getMainLooper()).postDelayed({
            startActivity(Intent(this, MainActivity::class.java))
            overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out)
            finish()
        }, 2200)
    }
}
