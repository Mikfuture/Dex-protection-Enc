package com.dex.enc

import android.animation.Animator
import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.util.AttributeSet
import android.view.View

/**
 * 单选圆点。
 *
 * 未勾选：空心圆（外圈常态色，没有实心点）。
 * 勾选  ：外圈保留，整体换成勾选色；里面出现实心点，从满格缩到 CHECKED_SCALE。
 * 取消  ：实心点先从 CHECKED_SCALE 撑回满格，然后圆心冒出一个小空心圆，
 *         向外扩大直到把实心块完全掏空；同时外圈颜色褪回常态色。
 */
class RadioDotView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
    private val ringPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE }
    private val path = Path()

    /** 勾选态：外圈和中间实心点共用这个颜色 */
    private val checkedColor = Color.parseColor("#4C7591")
    /** 未勾选态：外圈常态色 */
    private val idleColor = Color.parseColor("#C0C0C0")
    /** 当前外圈颜色（两个状态之间插值） */
    private var ringColor = idleColor
    private val ringStroke = 1.5f * resources.displayMetrics.density

    /** 圆盘半径倍率：1 = 和描边环同大，2/3 = 勾选后的缩小态 */
    private var discScale = 1f
    /** 中间被掏空的比例：0 = 实心，1 = 完全掏空（只剩描边环） */
    private var holeRatio = 1f

    private var animator: Animator? = null

    /** 当前真实状态。同一个状态重复设置时直接忽略，避免白跑一遍动画 */
    private var checked = false

    fun setCheckedState(checked: Boolean, animated: Boolean) {
        animator?.cancel()
        animator = null
        if (this.checked == checked) {
            if (!animated) {
                snapTo(checked)
                invalidate()
            }
            return
        }
        this.checked = checked
        if (!animated) {
            snapTo(checked)
            invalidate()
            return
        }
        if (checked) startFill() else startDrain()
    }

    /** 直接落到终态 */
    private fun snapTo(checked: Boolean) {
        discScale = if (checked) CHECKED_SCALE else 1f
        holeRatio = if (checked) 0f else 1f
        ringColor = if (checked) checkedColor else idleColor
    }

    /** 勾选：外圈保留，整体换成勾选色，实心点从满格缩到 CHECKED_SCALE */
    private fun startFill() {
        val anim = ValueAnimator.ofFloat(0f, 1f)
        anim.duration = 220L
        anim.addUpdateListener {
            val t = easeOut(it.animatedFraction)
            discScale = 1f - (1f - CHECKED_SCALE) * t
            holeRatio = 0f
            ringColor = lerpColor(idleColor, checkedColor, t)
            invalidate()
        }
        animator = anim
        anim.start()
    }

    /** 取消：实心点先撑回满格，再从圆心掏空；外圈颜色最后褪回常态色 */
    private fun startDrain() {
        val anim = ValueAnimator.ofFloat(0f, 1f)
        anim.duration = 380L
        anim.addUpdateListener {
            val p = it.animatedFraction
            if (p < GROW_PART) {
                // 撑开阶段：实心点和外圈都还是勾选色
                val t = easeOut(p / GROW_PART)
                discScale = CHECKED_SCALE + (1f - CHECKED_SCALE) * t
                holeRatio = 0f
                ringColor = checkedColor
            } else {
                // 掏空阶段：顺便把外圈颜色褪回常态色
                val t = easeOut((p - GROW_PART) / (1f - GROW_PART))
                discScale = 1f
                holeRatio = t
                ringColor = lerpColor(checkedColor, idleColor, t)
            }
            invalidate()
        }
        animator = anim
        anim.start()
    }

    /** 两色之间线性插值 */
    private fun lerpColor(from: Int, to: Int, t: Float): Int {
        val f = t.coerceIn(0f, 1f)
        return Color.argb(
            (Color.alpha(from) + (Color.alpha(to) - Color.alpha(from)) * f).toInt(),
            (Color.red(from) + (Color.red(to) - Color.red(from)) * f).toInt(),
            (Color.green(from) + (Color.green(to) - Color.green(from)) * f).toInt(),
            (Color.blue(from) + (Color.blue(to) - Color.blue(from)) * f).toInt()
        )
    }

    /** 先快后慢 */
    private fun easeOut(x: Float): Float {
        val c = x.coerceIn(0f, 1f)
        return 1f - (1f - c) * (1f - c)
    }

    override fun onDraw(canvas: Canvas) {
        val cx = width / 2f
        val cy = height / 2f
        val r = minOf(width, height) / 2f - ringStroke / 2f
        if (r <= 0f) return

        // 外圈描边：勾不勾选都保留这个大圆圈
        ringPaint.color = ringColor
        ringPaint.strokeWidth = ringStroke
        canvas.drawCircle(cx, cy, r, ringPaint)

        // 中间圆盘：外圆 + 反向内圆，用 EVEN_ODD 挖洞
        if (discScale > 0f && holeRatio < 1f) {
            val discR = r * discScale
            val holeR = discR * holeRatio
            path.reset()
            path.addCircle(cx, cy, discR, Path.Direction.CW)
            if (holeR > 0.5f) {
                path.addCircle(cx, cy, holeR, Path.Direction.CCW)
            }
            path.fillType = Path.FillType.EVEN_ODD
            fillPaint.color = checkedColor
            canvas.drawPath(path, fillPaint)
        }
    }

    companion object {
        private const val CHECKED_SCALE = 0.55f
        /** 取消动画里「撑开」占的比例，后面留给掏空 */
        private const val GROW_PART = 0.42f
    }
}
