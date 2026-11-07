package com.dex.enc

import android.content.Context
import android.util.AttributeSet
import android.widget.LinearLayout

/**
 * 幕后拉帘式布局。
 *
 * 普通 LinearLayout 在被外力收缩高度时，会把子 View 一起压扁：
 * 子 View 收到的是 AT_MOST(剩余高度)，TextView 会按变小的高度重新排版、
 * 换行位置跳动、文字被裁 —— 视觉上就是「闪一下」。
 *
 * 这里让子 View 永远按「不受限高度」测量：内容始终保持完整尺寸，
 * 外层高度只是把超出部分裁掉，于是收缩就是一道帘子从上往下落。
 */
class CurtainLayout @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : LinearLayout(context, attrs, defStyleAttr) {

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        // 先按不受限高度量，拿到「完全展开时」的真实内容尺寸
        super.onMeasure(
            widthMeasureSpec,
            MeasureSpec.makeMeasureSpec(0, MeasureSpec.UNSPECIFIED)
        )
        val naturalWidth = measuredWidth
        val naturalHeight = measuredHeight

        val limit = MeasureSpec.getSize(heightMeasureSpec)
        val clamped = when (MeasureSpec.getMode(heightMeasureSpec)) {
            MeasureSpec.EXACTLY -> if (limit < naturalHeight) limit else naturalHeight
            MeasureSpec.AT_MOST -> if (naturalHeight < limit) naturalHeight else limit
            else -> naturalHeight
        }

        setMeasuredDimension(naturalWidth, if (clamped > 0) clamped else 0)
    }
}
