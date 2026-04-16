package app.authentixsign

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.DashPathEffect
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF

class FingerprintView(context: Context, private val accentColor: Int, private val intense: Boolean = false) : android.view.View(context) {

    private val outerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = accentColor
        strokeWidth = if (intense) 3.6f else 2.4f
        if (!intense) pathEffect = DashPathEffect(floatArrayOf(6f, 4f), 0f)
    }

    private val arcPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = accentColor
        strokeWidth = if (intense) 3.6f else 3f
        strokeCap = Paint.Cap.ROUND
    }

    private val dotPaint = if (intense) Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = accentColor
        alpha = 128
    } else null

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val cx = width / 2f
        val cy = height / 2f
        val r = minOf(cx, cy) - 4f

        canvas.drawCircle(cx, cy, r, outerPaint)

        val arc1 = RectF(cx - r * 0.625f, cy - r * 0.625f, cx + r * 0.625f, cy + r * 0.625f)
        canvas.drawArc(arc1, 180f, 180f, false, arcPaint)

        val arc2 = RectF(cx - r * 0.375f, cy - r * 0.375f, cx + r * 0.375f, cy + r * 0.375f)
        canvas.drawArc(arc2, 180f, 180f, false, arcPaint)

        val arc3 = RectF(cx - r * 0.125f, cy - r * 0.25f, cx + r * 0.125f, cy + r * 0.15f)
        canvas.drawArc(arc3, 180f, 180f, false, arcPaint)

        val arc1r = RectF(cx - r * 0.625f, cy - r * 0.625f, cx + r * 0.625f, cy + r * 0.625f)
        canvas.drawArc(arc1r, 0f, -180f, false, arcPaint)

        val arc2r = RectF(cx - r * 0.375f, cy - r * 0.375f, cx + r * 0.375f, cy + r * 0.375f)
        canvas.drawArc(arc2r, 0f, -180f, false, arcPaint)

        dotPaint?.let {
            canvas.drawCircle(cx, cy, r * 0.15f, it)
        }
    }
}
