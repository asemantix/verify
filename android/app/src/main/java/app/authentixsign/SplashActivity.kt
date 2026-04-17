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
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView

/**
 * 2-second splash shown before [MainActivity]. Declared as the launcher
 * activity in AndroidManifest — this is the first thing the user sees.
 *
 * The whole screen is built programmatically (no layout XML) to stay
 * consistent with the rest of the app.
 */
class SplashActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setBackgroundColor(Color.parseColor("#f5f4f0"))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
        }

        val logo = ImageView(this).apply {
            setImageResource(R.drawable.ic_launcher_foreground)
        }
        val logoSize = (120 * resources.displayMetrics.density).toInt()
        root.addView(logo, LinearLayout.LayoutParams(logoSize, logoSize).apply {
            gravity = Gravity.CENTER_HORIZONTAL
        })

        val cormorantBold = androidx.core.content.res.ResourcesCompat.getFont(this, R.font.cormorant_garamond_bold)
            ?: Typeface.create("serif", Typeface.BOLD)
        val cormorantRegular = androidx.core.content.res.ResourcesCompat.getFont(this, R.font.cormorant_garamond_regular)
            ?: Typeface.create("serif", Typeface.NORMAL)

        val title = TextView(this).apply {
            text = "SÉSAME"
            setTextColor(Color.parseColor("#6655c0"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 48f)
            typeface = cormorantBold
            gravity = Gravity.CENTER
        }
        root.addView(title, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
            topMargin = (16 * resources.displayMetrics.density).toInt()
        })

        val slogan = TextView(this).apply {
            text = "Ouvre-toi !"
            setTextColor(Color.parseColor("#6a6860"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 24f)
            typeface = Typeface.create(cormorantRegular, Typeface.ITALIC)
            gravity = Gravity.CENTER
        }
        root.addView(slogan, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
            topMargin = (8 * resources.displayMetrics.density).toInt()
        })

        setContentView(root)

        // Fade-in: 900ms on the whole stack. Short enough that the 2-second
        // splash still feels snappy, long enough to read as "animated" not
        // "flash of content".
        val fade = AlphaAnimation(0f, 1f).apply {
            duration = 900
            fillAfter = true
        }
        root.startAnimation(fade)

        // Transition to MainActivity after 2s. Using postDelayed on the main
        // looper — no coroutine dependency needed for a one-shot timer.
        Handler(Looper.getMainLooper()).postDelayed({
            startActivity(Intent(this, MainActivity::class.java))
            // No slide animation — fade straight into the home screen so the
            // gold A doesn't jitter between positions.
            overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out)
            finish()
        }, 2000)
    }
}
