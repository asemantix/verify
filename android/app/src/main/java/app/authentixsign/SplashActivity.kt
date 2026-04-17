package app.authentixsign

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.view.animation.AlphaAnimation
import android.view.animation.Animation
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Interactive splash. The screen no longer auto-dismisses — the user must
 * tap "Ouvre-toi !" to continue. That tap fires a light EFFECT_CLICK
 * haptic and transitions to MainActivity.
 */
class SplashActivity : Activity() {

    @Volatile private var tapped = false
    @Volatile private var interactive = false

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

        root.addView(View(this), LinearLayout.LayoutParams(MATCH_PARENT, 0, 1.2f))

        val title = TextView(this).apply {
            text = "SÉSAME"
            setTextColor(Color.parseColor("#6655c0"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 72f)
            typeface = cormorantBold
            gravity = Gravity.CENTER
            alpha = 0f
        }
        root.addView(title, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        val slogan = TextView(this).apply {
            text = "Ouvre-toi !"
            setTextColor(Color.parseColor("#6a6860"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 32f)
            typeface = Typeface.create(cormorantRegular, Typeface.ITALIC)
            gravity = Gravity.CENTER
            alpha = 0f
            isClickable = true
            isFocusable = true
            setPadding(dp(32), dp(16), dp(32), dp(16))  // enlarge tap target
            setOnClickListener { onSlogan() }
        }
        root.addView(slogan, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
            topMargin = dp(8)
        })

        val subtitle = TextView(this).apply {
            text = "Votre doigt seul peut ouvrir."
            setTextColor(Color.parseColor("#aaa89e"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            typeface = jetbrainsMono
            gravity = Gravity.CENTER
            alpha = 0f
        }
        root.addView(subtitle, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
            topMargin = dp(18)
        })

        root.addView(View(this), LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))

        setContentView(root)

        val main = Handler(Looper.getMainLooper())

        // Stagger: SÉSAME fades in → slogan fades in → subtitle fades in and starts pulsing.
        title.animate().alpha(1f).setDuration(900).start()
        main.postDelayed({
            slogan.animate().alpha(1f).setDuration(800).start()
        }, 700)
        main.postDelayed({
            subtitle.animate().alpha(1f).setDuration(500).withEndAction {
                val pulse = AlphaAnimation(1f, 0.35f).apply {
                    duration = 1100
                    repeatMode = Animation.REVERSE
                    repeatCount = Animation.INFINITE
                    interpolator = android.view.animation.AccelerateDecelerateInterpolator()
                }
                subtitle.startAnimation(pulse)
            }.start()
            interactive = true
        }, 1500)
    }

    private fun onSlogan() {
        if (!interactive || tapped) return
        tapped = true
        playClickHaptic()
        startActivity(Intent(this, MainActivity::class.java))
        overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out)
        finish()
    }

    private fun playClickHaptic() {
        try {
            val v: Vibrator? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                (getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as? VibratorManager)?.defaultVibrator
            } else {
                @Suppress("DEPRECATION")
                getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
            }
            if (v == null || !v.hasVibrator()) return
            when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q ->
                    v.vibrate(VibrationEffect.createPredefined(VibrationEffect.EFFECT_CLICK))
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.O ->
                    v.vibrate(VibrationEffect.createOneShot(15L, VibrationEffect.DEFAULT_AMPLITUDE))
                else -> {
                    @Suppress("DEPRECATION")
                    v.vibrate(15L)
                }
            }
        } catch (_: Exception) { /* vibration is nice-to-have, never a blocker */ }
    }
}
