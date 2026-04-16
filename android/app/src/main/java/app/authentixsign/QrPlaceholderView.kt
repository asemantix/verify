package app.authentixsign

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF

class QrPlaceholderView(context: Context, private val accentColor: Int) : android.view.View(context) {

    private val strokePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = accentColor
        strokeWidth = 3f
    }

    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = accentColor
        alpha = 77
    }

    private val dotPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = accentColor
        alpha = 128
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val s = minOf(width, height).toFloat()
        val u = s / 10f

        // Top-left module
        canvas.drawRoundRect(RectF(u, u, u * 3.8f, u * 3.8f), 3f, 3f, strokePaint)
        canvas.drawRoundRect(RectF(u * 1.5f, u * 1.5f, u * 3.3f, u * 3.3f), 2f, 2f, fillPaint)

        // Top-right module
        canvas.drawRoundRect(RectF(u * 6.2f, u, u * 9f, u * 3.8f), 3f, 3f, strokePaint)
        canvas.drawRoundRect(RectF(u * 6.7f, u * 1.5f, u * 8.5f, u * 3.3f), 2f, 2f, fillPaint)

        // Bottom-left module
        canvas.drawRoundRect(RectF(u, u * 6.2f, u * 3.8f, u * 9f), 3f, 3f, strokePaint)
        canvas.drawRoundRect(RectF(u * 1.5f, u * 6.7f, u * 3.3f, u * 8.5f), 2f, 2f, fillPaint)

        // Data dots
        canvas.drawRoundRect(RectF(u * 6.2f, u * 6.2f, u * 7.2f, u * 7.2f), 2f, 2f, dotPaint)
        canvas.drawRoundRect(RectF(u * 7.8f, u * 6.2f, u * 8.8f, u * 7.2f), 2f, 2f, dotPaint)
        canvas.drawRoundRect(RectF(u * 6.2f, u * 7.8f, u * 7.2f, u * 8.8f), 2f, 2f, dotPaint)
        canvas.drawRoundRect(RectF(u * 7.8f, u * 7.8f, u * 8.8f, u * 8.8f), 2f, 2f, dotPaint)

        // Center pieces
        canvas.drawRoundRect(RectF(u * 4.3f, u, u * 5.5f, u * 2f), 2f, 2f, fillPaint)
        canvas.drawRoundRect(RectF(u * 4.3f, u * 4.3f, u * 5.5f, u * 5.5f), 2f, 2f, fillPaint)
        canvas.drawRoundRect(RectF(u, u * 4.3f, u * 2f, u * 5.5f), 2f, 2f, fillPaint)
    }
}
