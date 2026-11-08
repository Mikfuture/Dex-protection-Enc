package com.dex.enc

import android.Manifest
import android.widget.Switch
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.util.Base64
import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ValueAnimator
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.ProgressBar
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.common.collect.ImmutableSet
import org.jf.dexlib2.AccessFlags
import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcode
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.builder.MutableMethodImplementation
import org.jf.dexlib2.builder.instruction.*
import org.jf.dexlib2.iface.*
import org.jf.dexlib2.iface.instruction.OneRegisterInstruction
import org.jf.dexlib2.iface.instruction.ReferenceInstruction
import org.jf.dexlib2.iface.reference.StringReference
import org.jf.dexlib2.immutable.*
import org.jf.dexlib2.immutable.reference.ImmutableMethodReference
import org.jf.dexlib2.immutable.reference.ImmutableStringReference
import org.jf.dexlib2.immutable.reference.ImmutableTypeReference
import org.jf.dexlib2.rewriter.*
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class MainActivity : AppCompatActivity() {

    private lateinit var etPath: EditText
    private var selectedApkUri: Uri? = null
    private var selectedFileName: String? = null
    private val handler = Handler(Looper.getMainLooper())

    // --大烧货？
    private var encMethod = "AES"      
    private var encStrength = "low"
    private var antiDecrypt = false

private val openDocumentLauncher =
    registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
uri?.let {
    selectedApkUri = it
    selectedFileName = getFileNameFromUri(it) ?: "file.apk"
            val path = getRealPathFromUri(it)
            if (path != null) {
                etPath.setText(path)
            } else {
                etPath.setText(it.lastPathSegment ?: "已选择文件")
            }
        }
    }

    // 点击加密图标后要执行的动作，等权限授予后再调用
    private var pendingAfterPermission: (() -> Unit)? = null

    // Android 11+「所有文件访问权限」的申请结果
    private val manageStorageLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
                Environment.isExternalStorageManager()
            ) {
                runAfterPermission()
            } else {
                pendingAfterPermission = null
                Toast.makeText(this, "未授予「所有文件访问权限」", Toast.LENGTH_SHORT).show()
            }
        }

    // Android 10 及以下运行时存储权限的申请结果
    private val storagePermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) {
                runAfterPermission()
            } else {
                pendingAfterPermission = null
                Toast.makeText(this, "未授予存储权限", Toast.LENGTH_SHORT).show()
            }
        }

    /** 先申请存储权限，授权通过（或本就不需要）后再执行 action */
    private fun requestStoragePermissionThen(action: () -> Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Android 11+：用「所有文件访问权限」，才能写入 /sdcard/ApkEnc/
            if (Environment.isExternalStorageManager()) {
                action()
                return
            }
            pendingAfterPermission = action
            try {
                manageStorageLauncher.launch(
                    Intent(
                        android.provider.Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:$packageName")
                    )
                )
            } catch (e: Exception) {
                // 个别机型不支持带包名跳转，回退到权限列表页
                try {
                    manageStorageLauncher.launch(
                        Intent(android.provider.Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                    )
                } catch (_: Exception) {
                    pendingAfterPermission = null
                    Toast.makeText(this, "请手动开启「所有文件访问权限」", Toast.LENGTH_LONG).show()
                }
            }
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            // Android 6.0 ~ 10：运行时申请写外部存储
            val granted = ContextCompat.checkSelfPermission(
                this, Manifest.permission.WRITE_EXTERNAL_STORAGE
            ) == PackageManager.PERMISSION_GRANTED
            if (granted) {
                action()
            } else {
                pendingAfterPermission = action
                storagePermissionLauncher.launch(Manifest.permission.WRITE_EXTERNAL_STORAGE)
            }
        } else {
            action()
        }
    }

    private fun runAfterPermission() {
        val action = pendingAfterPermission
        pendingAfterPermission = null
        action?.invoke()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
etPath = findViewById(R.id.et_path)

        setupFunctionList()

        findViewById<ImageView>(R.id.iv_choose).setOnClickListener {
            openDocumentLauncher.launch("*/*")
        }

findViewById<ImageView>(R.id.iv_start).setOnClickListener {
    if (selectedApkUri == null) {
        Toast.makeText(this, "请先选择文件", Toast.LENGTH_SHORT).show()
        return@setOnClickListener
    }
    if (!dexEncryptChecked && !dexObfuscateChecked) {
        Toast.makeText(this, "请先勾选 Dex加密 或 Dex混淆", Toast.LENGTH_SHORT).show()
        return@setOnClickListener
    }
    // 先弹「Dex加密配置」圆角弹窗，点确定之后才申请权限、再进入选 DEX 的流程
    showDexConfigDialog {
        requestStoragePermissionThen {
            Thread {
        try {
            //  使用原始文件名，保留扩展名
            val fileName = selectedFileName ?: "input.apk"
            val cacheFile = File(cacheDir, fileName)
            contentResolver.openInputStream(selectedApkUri!!)?.use { input ->
                FileOutputStream(cacheFile).use { output ->
                    input.copyTo(output)
                }
            }
            handler.post { showEncryptDialog(cacheFile) }
        } catch (e: Exception) {
            handler.post {
                Toast.makeText(
                    this@MainActivity,
                    "读取文件失败: ${e.message}",
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
    }.start()
}
}
}
    }

private fun showEncryptDialog(inputApk: File) {
    // 从 XML 加载布局，替代掉原来的代码动态创建
    val rootView = layoutInflater.inflate(R.layout.dialog_encrypt, null)

    // 获取两大部分容器
    val panelSelect = rootView.findViewById<LinearLayout>(R.id.panel_select)
    val panelProgress = rootView.findViewById<LinearLayout>(R.id.panel_progress)

    // 选择面板的控件
    val lvDexFiles = rootView.findViewById<ListView>(R.id.lv_dex_files)
    val btnCancel = rootView.findViewById<TextView>(R.id.btn_cancel)
    val btnEncrypt = rootView.findViewById<TextView>(R.id.btn_encrypt)

    // 进度面板的控件
    val llLoading = rootView.findViewById<LinearLayout>(R.id.ll_loading)
    val progressBar = rootView.findViewById<ProgressBar>(R.id.progress_bar)
    val tvStatus = rootView.findViewById<TextView>(R.id.tv_status)
    val tvSuccess = rootView.findViewById<TextView>(R.id.tv_success)
    val btnCopy = rootView.findViewById<TextView>(R.id.btn_copy)
    val btnDismiss = rootView.findViewById<TextView>(R.id.btn_dismiss)

    val dialog = AlertDialog.Builder(this)
        .setView(rootView)
        .setCancelable(false)
        .create()
    dialog.window?.setBackgroundDrawableResource(android.R.color.transparent)
    dialog.show()

    btnCancel.setOnClickListener { dialog.dismiss() }

    btnCopy.setOnClickListener {
        val path = tvSuccess.text.toString()
        if (path.isNotEmpty()) {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("path", path))
            Toast.makeText(this, "已复制", Toast.LENGTH_SHORT).show()
        }
    }
    btnDismiss.setOnClickListener { dialog.dismiss() }

    btnEncrypt.setOnClickListener {
        panelSelect.visibility = View.GONE
        panelProgress.visibility = View.VISIBLE
        val checkedItems = lvDexFiles.checkedItemPositions
        val selectedDex = (0 until lvDexFiles.count)
            .filter { checkedItems.get(it) }
            .map { lvDexFiles.getItemAtPosition(it) as String }
        if (selectedDex.isEmpty()) {
            Toast.makeText(this, "未选中任何DEX文件", Toast.LENGTH_SHORT).show()
            return@setOnClickListener
        }
        doEncrypt(dialog, inputApk, selectedDex, llLoading, tvStatus, tvSuccess, btnCopy, btnDismiss)
    }

    // 后台获取 DEX 列表
    Thread {
        try {
            val dexEntries = mutableListOf<String>()
            if (inputApk.extension.equals("dex", true)) {
                dexEntries.add(inputApk.name)
            } else {
                ZipFile(inputApk).use { zip ->
                    val entries = zip.entries()
                    while (entries.hasMoreElements()) {
                        val name = entries.nextElement().name
                        if (name.matches(Regex("^classes(\\d+)?\\.dex$"))) {
                            dexEntries.add(name)
                        }
                    }
                }
            }
            val ordered = dexEntries.sortedBy { dexOrderIndex(it) }
            dexEntries.clear()
            dexEntries.addAll(ordered)

            if (dexEntries.isEmpty()) {
                handler.post {
                    Toast.makeText(this, "未找到有效DEX文件", Toast.LENGTH_SHORT).show()
                    dialog.dismiss()
                }
                return@Thread
            }
            val adapter = ArrayAdapter(
                this,
                android.R.layout.simple_list_item_multiple_choice,
                dexEntries
            )
            handler.post {
                lvDexFiles.adapter = adapter
                for (i in 0 until dexEntries.size) {
                    lvDexFiles.setItemChecked(i, true)
                }
            }
        } catch (e: Exception) {
            handler.post {
                Toast.makeText(this, "读取失败: ${e.message}", Toast.LENGTH_SHORT).show()
                dialog.dismiss()
            }
        }
    }.start()
}

    private fun doEncrypt(
        dialog: AlertDialog,
        inputApk: File,
        selectedDex: List<String>,
        llLoading: LinearLayout,
        tvStatus: TextView,
        tvSuccess: TextView,
        btnCopy: TextView,
        btnDismiss: TextView
    ) {
        val doEnc = dexEncryptChecked
        val doObf = dexObfuscateChecked
        val scheme = buildScheme(encMethod, encStrength)
        val usePool = doEnc && antiDecrypt
        val outPrefix = when {
            doObf && doEnc -> "obf_enc_"
            doObf -> "obf_"
            else -> "enc_"
        }
        Thread {
            try {
                // 先把要处理的 DEX 全部读进内存
                var dexBytesList = mutableListOf<Pair<String, ByteArray>>()
                for (dexName in selectedDex) {
                    val bytes = if (inputApk.extension.equals("dex", true)) {
                        inputApk.readBytes()
                    } else {
                        ZipFile(inputApk).use {
                            it.getInputStream(it.getEntry(dexName)!!).readBytes()
                        }
                    }
                    dexBytesList.add(dexName to bytes)
                }

                // 1) 字符串加密（StringFog）：一字符串一随机密钥 + 重复密钥 XOR。
                //    不碰类名/方法名、不改控制流，所以不会有反射兼容问题。
                if (doObf) {
                    handler.post { tvStatus.text = "正在加密字符串..." }
                    dexBytesList = StringFogObfuscator
                        .apply(
                            dexBytesList,
                            cacheDir,
                            FogOptions(fogEnabled, fogKeyLength, fogEnhanced, fogJunk)
                        )
                        .toMutableList()
                    handler.post { tvStatus.text = "字符串加密完成" }
                }

                // 2) 再加密。防字符串解密：跨 DEX 统一建池，保证每个 dex 里的索引一致
                val stringIndexMap: Map<String, Int> = if (usePool) {
                    handler.post { tvStatus.text = "正在收集字符串池..." }
                    collectStringPoolMap(dexBytesList.map { it.second })
                } else {
                    emptyMap()
                }

                val modifiedDexMap = mutableMapOf<String, ByteArray>()
                for ((index, item) in dexBytesList.withIndex()) {
                    val dexName = item.first
                    if (!doEnc) {
                        // 只勾了混淆：原样写回处理后的字节
                        modifiedDexMap[dexName] = item.second
                        continue
                    }
                    handler.post {
                        tvStatus.text = "正在加密 $dexName (${index + 1}/${dexBytesList.size})..."
                    }
                    modifiedDexMap[dexName] = processSingleDex(
                        item.second,
                        index == 0,
                        scheme,
                        stringIndexMap
                    )
                    handler.post {
                        tvStatus.text = "$dexName 加密成功 (${index + 1}/${dexBytesList.size})"
                    }
                }

                if (inputApk.extension.equals("dex", true)) {
                    // 单独DEX：直接输出，不显示"请签名"
                    val outputDex = File(getSafeOutputDirectory(), "$outPrefix${inputApk.name}")
                    FileOutputStream(outputDex).use { it.write(modifiedDexMap.values.first()) }
                    handler.post {
                        llLoading.visibility = View.GONE
                        tvSuccess.text = outputDex.absolutePath
                        tvSuccess.visibility = View.VISIBLE
                        btnCopy.visibility = View.VISIBLE
                        btnDismiss.visibility = View.VISIBLE
                    }
                } else {
                    // APK：重新打包
                    handler.post { tvStatus.text = "正在重新打包 APK..." }
                    val outputApk = File(getSafeOutputDirectory(), "$outPrefix${inputApk.name}")
                    repackApk(inputApk, modifiedDexMap, outputApk)
                    handler.post {
                        llLoading.visibility = View.GONE
                        tvSuccess.text = "${outputApk.absolutePath}"
                        tvSuccess.visibility = View.VISIBLE
                        btnCopy.visibility = View.VISIBLE
                        btnDismiss.visibility = View.VISIBLE
                    }
                }
            } catch (e: Exception) {
                handler.post { tvStatus.text = "失败: ${e.message}" }
            }
        }.start()
    }


    private fun dexOrderIndex(name: String): Int {
        val lower = name.lowercase()
        if (!lower.endsWith(".dex")) return 1
        val mid = lower.removeSuffix(".dex").removePrefix("classes")
        return mid.toIntOrNull() ?: 1
    }



    /** 把加密配置的 UI 绑到给定根视图上（配置弹窗用） */
    private fun bindEncryptOptions(root: View) {
        val methodRow = root.findViewById<LinearLayout>(R.id.ll_method_row)
        val methodArrow = root.findViewById<TextView>(R.id.tv_method_arrow)
        val methodValue = root.findViewById<TextView>(R.id.tv_method_value)
        val methodOptions = root.findViewById<LinearLayout>(R.id.ll_method_options)
        val strengthRow = root.findViewById<LinearLayout>(R.id.ll_strength_row)
        val strengthArrow = root.findViewById<TextView>(R.id.tv_strength_arrow)
        val strengthValue = root.findViewById<TextView>(R.id.tv_strength_value)
        val strengthOptions = root.findViewById<LinearLayout>(R.id.ll_strength_options)

        val swAnti = root.findViewById<Switch>(R.id.sw_anti_decrypt)
        // 先复位再挂监听，避免程序化设置时反过来触发回调
        swAnti.isChecked = antiDecrypt
        swAnti.setOnCheckedChangeListener { _, checked -> antiDecrypt = checked }

        val methodViews = listOf(
            "Base64" to root.findViewById<TextView>(R.id.op_method_base64),
            "AES" to root.findViewById<TextView>(R.id.op_method_aes),
            "DES" to root.findViewById<TextView>(R.id.op_method_des),
            "RC4" to root.findViewById<TextView>(R.id.op_method_rc4)
        )
        val strengthViews = listOf(
            "low" to root.findViewById<TextView>(R.id.op_strength_low),
            "medium" to root.findViewById<TextView>(R.id.op_strength_medium),
            "high" to root.findViewById<TextView>(R.id.op_strength_high)
        )

        fun paint(view: TextView, selected: Boolean, label: String) {
            view.text = (if (selected) "● " else "○ ") + label
            view.setTextColor(Color.parseColor(if (selected) "#4C7591" else "#555555"))
            view.setTypeface(null, if (selected) Typeface.BOLD else Typeface.NORMAL)
        }

        fun renderMethod() {
            methodValue.text = encMethod
            methodViews.forEach { (key, view) -> paint(view, key == encMethod, METHOD_LABELS[key] ?: key) }
        }

        fun renderStrength() {
            strengthValue.text = STRENGTH_LABELS[encStrength] ?: "低"
            strengthViews.forEach { (key, view) -> paint(view, key == encStrength, STRENGTH_TEXTS[key] ?: key) }
        }

        // 抽屉开合：弹出/收回都是「先快后慢」，起步最猛，越接近终点越稳
        methodRow.setOnClickListener { toggleDrawer(methodOptions, methodArrow) }
        strengthRow.setOnClickListener { toggleDrawer(strengthOptions, strengthArrow) }
        methodViews.forEach { (key, view) ->
            view.setOnClickListener {
                encMethod = key
                renderMethod()
            }
        }
        strengthViews.forEach { (key, view) ->
            view.setOnClickListener {
                encStrength = key
                renderStrength()
            }
        }

        renderMethod()
        renderStrength()
    }

    // ============ 功能选择：Dex加密 / Dex混淆（单选，空心圆 → 实心） ============

    private var dexEncryptChecked = false
    private var dexObfuscateChecked = false

    // StringFog 配置
    private var fogEnabled = true
    private var fogKeyLength = 8
    private var fogEnhanced = false
    private var fogJunk = 5

    private fun setupFunctionList() {
        val encRow = findViewById<View>(R.id.row_dex_encrypt)
        val encDot = findViewById<RadioDotView>(R.id.v_dex_radio)
        val obfRow = findViewById<View>(R.id.row_dex_obfuscate)
        val obfDot = findViewById<RadioDotView>(R.id.v_dex_obf_radio)

        // 只能选一个：勾上自己就把另一个取消
        encRow.setOnClickListener {
            dexEncryptChecked = !dexEncryptChecked
            if (dexEncryptChecked) dexObfuscateChecked = false
            encDot.setCheckedState(dexEncryptChecked, true)
            obfDot.setCheckedState(dexObfuscateChecked, true)
        }
        obfRow.setOnClickListener {
            dexObfuscateChecked = !dexObfuscateChecked
            if (dexObfuscateChecked) dexEncryptChecked = false
            encDot.setCheckedState(dexEncryptChecked, true)
            obfDot.setCheckedState(dexObfuscateChecked, true)
        }

        encDot.setCheckedState(dexEncryptChecked, false)
        obfDot.setCheckedState(dexObfuscateChecked, false)
    }

    /** 把混淆配置（StringFog）的 UI 绑到给定根视图上 */
    private fun bindObfuscationOptions(root: View) {
        val swEnable = root.findViewById<Switch>(R.id.sw_fog_enable)
        swEnable.isChecked = fogEnabled
        swEnable.setOnCheckedChangeListener { _, checked -> fogEnabled = checked }

        val keyRow = root.findViewById<LinearLayout>(R.id.ll_fog_key_row)
        val keyArrow = root.findViewById<TextView>(R.id.tv_fog_key_arrow)
        val keyValue = root.findViewById<TextView>(R.id.tv_fog_key_value)
        val keyOptions = root.findViewById<LinearLayout>(R.id.ll_fog_key_options)

        val keyViews = listOf(
            4 to root.findViewById<TextView>(R.id.op_fog_4),
            8 to root.findViewById<TextView>(R.id.op_fog_8),
            16 to root.findViewById<TextView>(R.id.op_fog_16)
        )

        fun paint(view: TextView, selected: Boolean, label: String) {
            view.text = (if (selected) "● " else "○ ") + label
            view.setTextColor(Color.parseColor(if (selected) "#4C7591" else "#555555"))
            view.setTypeface(null, if (selected) Typeface.BOLD else Typeface.NORMAL)
        }

        fun renderKey() {
            keyValue.text = "$fogKeyLength"
            keyViews.forEach { (len, view) ->
                paint(view, len == fogKeyLength, if (len == 8) "8 字节（推荐）" else "$len 字节")
            }
        }

        keyRow.setOnClickListener { toggleDrawer(keyOptions, keyArrow) }
        keyViews.forEach { (len, view) ->
            view.setOnClickListener {
                fogKeyLength = len
                renderKey()
            }
        }
        renderKey()

        val swEnhanced = root.findViewById<Switch>(R.id.sw_fog_enhanced)
        val junkPanel = root.findViewById<View>(R.id.ll_junk_panel)

        swEnhanced.isChecked = fogEnhanced
        swEnhanced.setOnCheckedChangeListener { _, checked ->
            fogEnhanced = checked
            // 和两个抽屉同一套：高度 0 <-> 内容高度，先快后慢
            animateDrawer(junkPanel, checked)
        }
        // 打开弹窗时如果增强已经开着，把面板撑开
        if (fogEnhanced) animateDrawer(junkPanel, true)

        // 垃圾倍率：滑动条，进度 0..99 对应 1..100 条
        val sbJunk = root.findViewById<android.widget.SeekBar>(R.id.sb_junk)
        val tvJunk = root.findViewById<TextView>(R.id.tv_junk_value)
        sbJunk.max = 99
        sbJunk.progress = (fogJunk - 1).coerceIn(0, 99)
        tvJunk.text = "$fogJunk"
        sbJunk.setOnSeekBarChangeListener(object : android.widget.SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(
                seekBar: android.widget.SeekBar?,
                progress: Int,
                fromUser: Boolean
            ) {
                fogJunk = progress + 1
                tvJunk.text = "$fogJunk"
            }

            override fun onStartTrackingTouch(seekBar: android.widget.SeekBar?) {}

            override fun onStopTrackingTouch(seekBar: android.widget.SeekBar?) {}
        })
    }

    // ============ 配置弹窗（Activity 内遮罩层实现） ============
    //
    // 不用 AlertDialog：Dialog 是独立 Window，内容高度一变就要 relayout 窗口
    // （一次 IPC + surface 调整），高度动画每帧都会触发，抽屉就会卡。
    // 放进 Activity 自己的窗口里，窗口尺寸恒为 match_parent，每帧只重排这棵小子树。

    private var configOverlay: View? = null
    private var configCard: View? = null
    private var configClosing = false

    /**
     * 「Dex加密配置」弹窗。
     * 圆角，样式与「选择要加密的DEX」弹窗一致；左下取消、右下确定。
     * 确定之后才回到正常流程：申请权限 -> 勾选 DEX -> 加密。
     *
     * 进场：遮罩先淡入，卡片稍慢一点淡入并从 0.88 放大到 1（先快后慢）。
     */
    private fun showDexConfigDialog(onConfirm: () -> Unit) {
        // 保险：清掉可能残留的旧遮罩
        configOverlay?.let { (it.parent as? ViewGroup)?.removeView(it) }
        configOverlay = null
        configCard = null
        configClosing = false

        val content = findViewById<FrameLayout>(android.R.id.content)
        val overlay = layoutInflater.inflate(R.layout.overlay_dex_config, content, false)
        content.addView(
            overlay,
            FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )
        )
        configOverlay = overlay

        val scrim = overlay.findViewById<View>(R.id.config_scrim)
        val card = overlay.findViewById<View>(R.id.config_card)
        configCard = card

        // 标题与分区：勾了哪个就只显示哪个的配置，两个都勾就都显示
        val title = overlay.findViewById<TextView>(R.id.tv_config_title)
        val sectionEncrypt = overlay.findViewById<View>(R.id.section_encrypt)
        val sectionObfuscate = overlay.findViewById<View>(R.id.section_obfuscate)
        when {
            dexEncryptChecked && dexObfuscateChecked -> {
                title.text = "Dex配置"
                sectionEncrypt.visibility = View.VISIBLE
                sectionObfuscate.visibility = View.VISIBLE
            }
            dexObfuscateChecked -> {
                title.text = "Dex混淆配置"
                sectionEncrypt.visibility = View.GONE
                sectionObfuscate.visibility = View.VISIBLE
            }
            else -> {
                title.text = "Dex加密配置"
                sectionEncrypt.visibility = View.VISIBLE
                sectionObfuscate.visibility = View.GONE
            }
        }

        bindEncryptOptions(overlay)
        bindObfuscationOptions(overlay)

        overlay.findViewById<TextView>(R.id.btn_config_cancel).setOnClickListener {
            dismissDexConfig()
        }
        overlay.findViewById<TextView>(R.id.btn_config_ok).setOnClickListener {
            dismissDexConfig(onDone = onConfirm)
        }
        // 点弹窗外的空白处（遮罩）= 返回，直接关掉
        // 卡片在 XML 里设了 clickable=true，所以点卡片本身不会误触到这里
        overlay.setOnClickListener { dismissDexConfig() }

        // ===== 进场动画 =====
        // 遮罩先淡入，卡片稍慢，同时从 0.88 放大到 1，就有「弹出来」的渐显感
        scrim.alpha = 0f
        scrim.animate()
            .alpha(1f)
            .setDuration(OVERLAY_SCRIM_MS)
            .start()

        card.scaleX = 0.88f
        card.scaleY = 0.88f
        card.alpha = 0f
        card.animate()
            .alpha(1f)
            .scaleX(1f)
            .scaleY(1f)
            .setDuration(OVERLAY_CARD_MS)
            .setInterpolator(DecelerateInterpolator(1.6f))
            .start()
    }

    /**
     * 关掉配置弹窗。
     * immediate = true 直接移除；否则先播收回动画，动画结束再移除并回调 onDone。
     */
    private fun dismissDexConfig(immediate: Boolean = false, onDone: (() -> Unit)? = null) {
        val overlay = configOverlay ?: return
        if (configClosing) return
        configClosing = true

        val card = configCard
        // 抽屉 View 每次都新建，关掉时把动画/开合状态清掉，别攒引用
        drawerAnimators.clear()
        openDrawers.clear()

        val finish = Runnable {
            if (configOverlay === overlay) {
                configOverlay = null
                configCard = null
            }
            configClosing = false
            (overlay.parent as? ViewGroup)?.removeView(overlay)
            onDone?.invoke()
        }

        if (immediate || !overlay.isAttachedToWindow) {
            finish.run()
            return
        }

        // ===== 收回动画 =====
        // 整体淡出，卡片同时微微缩小
        if (card != null) {
            card.animate()
                .scaleX(0.94f)
                .scaleY(0.94f)
                .setDuration(OVERLAY_EXIT_MS)
                .start()
        }
        overlay.animate()
            .alpha(0f)
            .setDuration(OVERLAY_EXIT_MS)
            .withEndAction(finish)
            .start()
    }

    @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
    override fun onBackPressed() {
        if (configOverlay != null) {
            dismissDexConfig()
        } else {
            super.onBackPressed()
        }
    }

    // ============ 抽屉动画：先快后慢 ============

    private val drawerAnimators = mutableMapOf<View, ValueAnimator>()

    /** 抽屉的逻辑开合状态。不能靠 visibility 判断——面板全程 visible，只是高度在变 */
    private val openDrawers = mutableSetOf<View>()

    private fun toggleDrawer(panel: View, arrow: TextView) {
        val opening = panel !in openDrawers
        if (opening) openDrawers.add(panel) else openDrawers.remove(panel)
        arrow.text = if (opening) "▴" else "▾"
        animateDrawer(panel, opening)
    }


    private fun animateDrawer(panel: View, opening: Boolean) {
        // 连点保护：先掉上一条动画，再拿当前高度作为起点
        drawerAnimators.remove(panel)?.cancel()

        val start = panel.height
        // 只有展开需要量内容高度；收缩时多量一次只会让子 View 白跑一遍排版
        val target = if (opening) measureDrawerContent(panel) else 0

        // 只改 height 字段 + requestLayout，不整块重设 layoutParams
        val lp = panel.layoutParams
        if (lp.height != start) {
            lp.height = start
            panel.requestLayout()
        }

        if (start == target) {
            finishDrawer(panel, opening)
            return
        }

        val animator = ValueAnimator.ofInt(start, target)
        animator.duration = DRAWER_DURATION_MS
        animator.interpolator = DecelerateInterpolator(DRAWER_DECELERATE_FACTOR)
        animator.addUpdateListener { anim ->
            val h = anim.animatedValue as Int
            val params = panel.layoutParams
            if (params.height != h) {
                params.height = h
                panel.requestLayout()
            }
        }
        animator.addListener(object : AnimatorListenerAdapter() {
            override fun onAnimationEnd(animation: Animator) {
                // 被新动画抢占时不要收尾，否则会瞬跳
                if (drawerAnimators[panel] === animation) {
                    drawerAnimators.remove(panel)
                    finishDrawer(panel, opening)
                }
            }
        })
        drawerAnimators[panel] = animator
        animator.start()
    }

    private fun finishDrawer(panel: View, opening: Boolean) {
        // 收尾只把高度落定：展开回到 WRAP_CONTENT，收起就留在 0。
        // 没有任何可见性变更，所以不会有最后一帧的闪。
        val lp = panel.layoutParams
        val settled = if (opening) ViewGroup.LayoutParams.WRAP_CONTENT else 0
        if (lp.height != settled) {
            lp.height = settled
            panel.requestLayout()
        }
    }

    /** 量出抽屉完全展开后的高度（高度 0 状态下也能量） */
    private fun measureDrawerContent(panel: View): Int {
        // 用父容器的「内容宽度」量，必须减掉 padding，不能直接用 parent.width。
        // 量宽了文字换行位置会算错，展开到最后一下会抽。
        val parent = panel.parent as? View
        val parentContentWidth = if (parent != null) {
            parent.width - parent.paddingLeft - parent.paddingRight
        } else 0
        val width = if (parentContentWidth > 0) parentContentWidth else resources.displayMetrics.widthPixels
        panel.measure(
            View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY),
            View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED)
        )
        return panel.measuredHeight
    }

    /** 加密方案：算法 / JCE 名 / Cipher 变换串 / 密钥字面量 */
    private class EncScheme(
        val method: String,
        val jceName: String,
        val transform: String,
        val keyText: String
    )

    private fun keyTextFor(strength: String): String {
        val base = "MySecureKey12345ForgeCinderK7x9QzPaBv2NmLd5"
        val len = when (strength) {
            "medium" -> 24
            "high" -> 32
            else -> 16
        }
        return base.take(len)
    }

    private fun buildScheme(method: String, strength: String): EncScheme {
        val keyText = keyTextFor(strength)
        return when (method) {
            "Base64" -> EncScheme("Base64", "", "", "")
            "DES" -> EncScheme("DES", "DES", "DES/ECB/PKCS5Padding", keyText.take(8))
            "RC4" -> EncScheme("RC4", "ARCFOUR", "ARCFOUR", keyText)
            else -> EncScheme("AES", "AES", "AES/ECB/PKCS5Padding", keyText)
        }
    }

    /** 把明文压成密文串（统一用 Base64 承载，方便以 const-string 存放） */
    private fun encryptPayload(plain: String, scheme: EncScheme): String {
        val raw = plain.toByteArray(Charsets.UTF_8)
        val payload: ByteArray = if (scheme.method == "Base64") {
            raw
        } else {
            val cipher = Cipher.getInstance(scheme.transform)
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(scheme.keyText.toByteArray(Charsets.UTF_8), scheme.jceName)
            )
            cipher.doFinal(raw)
        }
        return Base64.encodeToString(payload, Base64.NO_WRAP)
    }

    /** 防字符串解密：跨全部 DEX 收一收字符串，统一编号（超上限的保持就地加密） */
    private fun collectStringPoolMap(dexBytesList: List<ByteArray>): Map<String, Int> {
        val pool = linkedSetOf<String>()
        val opcodes = Opcodes.getDefault()
        for ((i, bytes) in dexBytesList.withIndex()) {
            val scanFile = File(cacheDir, "scan_pool_$i.dex")
            try {
                scanFile.writeBytes(bytes)
                val dex = DexFileFactory.loadDexFile(scanFile, opcodes)
                for (classDef in dex.classes) {
                    if (classDef.type == "Lcom/secure/Decryptor;" ||
                        classDef.type == "Lcom/secure/StringPool;"
                    ) continue
                    for (method in classDef.methods) {
                        val impl = method.implementation ?: continue
                        for (ins in impl.instructions) {
                            if (ins is ReferenceInstruction && ins.reference is StringReference) {
                                pool.add((ins.reference as StringReference).string)
                            }
                        }
                    }
                }
            } catch (_: Exception) {
            } finally {
                scanFile.delete()
            }
        }
        val selected = pool
            .filter { it.length >= 2 }
            .sortedByDescending { it.length }
            .take(MAX_POOL_STRINGS)
        val map = linkedMapOf<String, Int>()
        selected.forEachIndexed { index, s -> map[s] = index }
        return map
    }

    private fun buildEncryptedPool(map: Map<String, Int>, scheme: EncScheme): List<String> {
        val max = map.values.maxOrNull() ?: return emptyList()
        val arr = MutableList(max + 1) { "" }
        map.forEach { (plain, index) -> arr[index] = encryptPayload(plain, scheme) }
        return arr
    }

    private fun getSafeOutputDirectory(): File {
        // Android 11+：优先输出到公共目录 /sdcard/ApkEnc/（需要 MANAGE_EXTERNAL_STORAGE）
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (Environment.isExternalStorageManager()) {
                val publicDir = File(Environment.getExternalStorageDirectory(), "ApkEnc")
                if (publicDir.exists() || publicDir.mkdirs()) {
                    return publicDir
                }
            } else {
                // 未授权时跳转到「所有文件访问权限」设置页，本次先回退到私有目录
                try {
                    val intent = android.content.Intent(
                        android.provider.Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:$packageName")
                    )
                    startActivity(intent)
                    handler.post {
                        Toast.makeText(
                            this,
                            "请开启「所有文件访问权限」，开启后重新加密即可输出到 /sdcard/ApkEnc/",
                            Toast.LENGTH_LONG
                        ).show()
                    }
                } catch (_: Exception) {
                }
            }
        } else {
            // Android 10 及以下：有 WRITE_EXTERNAL_STORAGE 就能直接写公共目录
            val publicDir = File(Environment.getExternalStorageDirectory(), "ApkEnc")
            if (publicDir.exists() || publicDir.mkdirs()) {
                return publicDir
            }
        }
        val dir = getExternalFilesDir("DexEnc") ?: cacheDir
        if (!dir.exists()) dir.mkdirs()
        return dir
    }


private fun getFileNameFromUri(uri: Uri): String? {
    var name: String? = null
    contentResolver.query(uri, null, null, null, null)?.use { cursor ->
        if (cursor.moveToFirst()) {
            val nameIndex = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (nameIndex >= 0) {
                name = cursor.getString(nameIndex)
            }
        }
    }
    if (name == null) {
        name = uri.lastPathSegment
            ?.substringAfterLast('/')
            ?.substringAfter(':')
    }
    if (name == null) name = "unknown"
    return name
}

private fun getRealPathFromUri(uri: Uri): String? {
    if ("file".equals(uri.scheme, ignoreCase = true)) return uri.path
    try {
        contentResolver.query(uri, arrayOf(MediaStore.MediaColumns.DATA), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val path = cursor.getString(cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.DATA))
                if (path != null && File(path).exists()) return path
            }
        }
    } catch (_: Exception) { }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
        try {
            if (android.provider.DocumentsContract.isDocumentUri(this, uri)) {
                val docId = android.provider.DocumentsContract.getDocumentId(uri)
                if ("com.android.externalstorage.documents" == uri.authority) {
                    val split = docId.split(":")
                    if (split.size >= 2 && "primary".equals(split[0], ignoreCase = true)) {
                        return "${Environment.getExternalStorageDirectory()}/${split[1]}"
                    }
                }
            }
        } catch (_: Exception) { }
    }
    return null
}
    private fun processSingleDex(
        dexBytes: ByteArray,
        injectDecryptor: Boolean,
        scheme: EncScheme,
        stringIndexMap: Map<String, Int>
    ): ByteArray {
        val tempIn = File(cacheDir, "temp_in.dex")
        tempIn.writeBytes(dexBytes)
        val opcodes = Opcodes.getDefault()
        val originalDex = DexFileFactory.loadDexFile(tempIn, opcodes)
        val rewrittenDex = createDexRewriter(scheme, stringIndexMap).getDexFileRewriter().rewrite(originalDex)
        val allClasses = rewrittenDex.classes.mapTo(mutableSetOf<ClassDef>()) { it }
        if (injectDecryptor) {
            allClasses.add(buildDecryptorClass(scheme))
            if (stringIndexMap.isNotEmpty()) {
                allClasses.add(buildStringPoolClass(buildEncryptedPool(stringIndexMap, scheme)))
            }
        }
        val tempOut = File(cacheDir, "temp_out.dex")
        DexFileFactory.writeDexFile(tempOut.absolutePath, ImmutableDexFile(opcodes, allClasses))
        val result = tempOut.readBytes()
        tempIn.delete()
        tempOut.delete()
        return result
    }

    private fun buildStringPoolClass(encStrings: List<String>): ClassDef {
        val classType = "Lcom/secure/StringPool;"
        val arrayField = ImmutableField(
            classType, "S", "[Ljava/lang/String;",
            AccessFlags.PRIVATE.value or AccessFlags.STATIC.value or AccessFlags.FINAL.value,
            null, ImmutableSet.of(), ImmutableSet.of()
        )
        val clinit = MutableMethodImplementation(3)
        val size = encStrings.size
        if (size <= 7) {
            clinit.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 0, size))
        } else {
            clinit.addInstruction(BuilderInstruction21s(Opcode.CONST_16, 0, size))
        }
        clinit.addInstruction(
            BuilderInstruction22c(Opcode.NEW_ARRAY, 1, 0, ImmutableTypeReference("[Ljava/lang/String;"))
        )
        encStrings.forEachIndexed { i, s ->
            clinit.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, 0, ImmutableStringReference(s)))
            if (i <= 7) {
                clinit.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 2, i))
            } else {
                clinit.addInstruction(BuilderInstruction21s(Opcode.CONST_16, 2, i))
            }
            clinit.addInstruction(BuilderInstruction23x(Opcode.APUT_OBJECT, 0, 1, 2))
        }
        clinit.addInstruction(BuilderInstruction21c(Opcode.SPUT_OBJECT, 1, arrayField))
        clinit.addInstruction(BuilderInstruction10x(Opcode.RETURN_VOID))

        val get = MutableMethodImplementation(3)
        get.addInstruction(BuilderInstruction21c(Opcode.SGET_OBJECT, 0, arrayField))
        get.addInstruction(BuilderInstruction23x(Opcode.AGET_OBJECT, 1, 0, 2))
        get.addInstruction(
            BuilderInstruction35c(
                Opcode.INVOKE_STATIC, 1, 1, 0, 0, 0, 0,
                ImmutableMethodReference("Lcom/secure/Decryptor;", "decrypt", listOf("Ljava/lang/String;"), "Ljava/lang/String;")
            )
        )
        get.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0))
        get.addInstruction(BuilderInstruction11x(Opcode.RETURN_OBJECT, 0))

        return ImmutableClassDef(
            classType, AccessFlags.PUBLIC.value, "Ljava/lang/Object;",
            emptyList(), null, ImmutableSet.of(), listOf(arrayField), emptyList(),
            listOf(
                ImmutableMethod(classType, "<clinit>", emptyList(), "V", AccessFlags.STATIC.value or AccessFlags.CONSTRUCTOR.value, ImmutableSet.of(), ImmutableSet.of(), clinit),
                ImmutableMethod(classType, "get", listOf(ImmutableMethodParameter("I", ImmutableSet.of(), null)), "Ljava/lang/String;", AccessFlags.PUBLIC.value or AccessFlags.STATIC.value, ImmutableSet.of(), ImmutableSet.of(), get)
            ), emptyList()
        )
    }

    private fun buildDecryptorClass(scheme: EncScheme): ClassDef {
        val ct = "Lcom/secure/Decryptor;"
        val b64Decode = ImmutableMethodReference(
            "Landroid/util/Base64;", "decode",
            listOf("Ljava/lang/String;", "I"), "[B"
        )
        val strInit = ImmutableMethodReference("Ljava/lang/String;", "<init>", listOf("[B"), "V")

        // 纯 Base64：不做密码运算，解码后直接还原字符串
        if (scheme.method == "Base64") {
            val di = MutableMethodImplementation(3)
            di.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 0, 0))
            di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 2, 0, 0, 0, 0, b64Decode))
            di.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1))
            di.addInstruction(BuilderInstruction21c(Opcode.NEW_INSTANCE, 0, ImmutableTypeReference("Ljava/lang/String;")))
            di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_DIRECT, 2, 0, 1, 0, 0, 0, strInit))
            di.addInstruction(BuilderInstruction11x(Opcode.RETURN_OBJECT, 0))
            return ImmutableClassDef(
                ct, AccessFlags.PUBLIC.value, "Ljava/lang/Object;",
                emptyList(), null, ImmutableSet.of(), emptyList(), emptyList(),
                listOf(
                    ImmutableMethod(ct, "decrypt", listOf(ImmutableMethodParameter("Ljava/lang/String;", ImmutableSet.of(), null)), "Ljava/lang/String;", AccessFlags.PUBLIC.value or AccessFlags.STATIC.value, ImmutableSet.of(), ImmutableSet.of(), di)
                ), emptyList()
            )
        }

        val kf = ImmutableField(ct, "key", "[B", AccessFlags.PRIVATE.value or AccessFlags.STATIC.value, null, ImmutableSet.of(), ImmutableSet.of())

        val ci = MutableMethodImplementation(2)
        ci.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, 0, ImmutableStringReference(scheme.keyText)))
        ci.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0, ImmutableMethodReference("Ljava/lang/String;", "getBytes", emptyList(), "[B")))
        ci.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1))
        ci.addInstruction(BuilderInstruction21c(Opcode.SPUT_OBJECT, 1, kf))
        ci.addInstruction(BuilderInstruction10x(Opcode.RETURN_VOID))

        val di = MutableMethodImplementation(5)
        di.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 0, 0))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 4, 0, 0, 0, 0, b64Decode))
        di.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1))
        di.addInstruction(BuilderInstruction21c(Opcode.NEW_INSTANCE, 2, ImmutableTypeReference("Ljavax/crypto/spec/SecretKeySpec;")))
        di.addInstruction(BuilderInstruction21c(Opcode.SGET_OBJECT, 0, kf))
        di.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, 3, ImmutableStringReference(scheme.jceName)))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_DIRECT, 3, 2, 0, 3, 0, 0, ImmutableMethodReference("Ljavax/crypto/spec/SecretKeySpec;", "<init>", listOf("[B", "Ljava/lang/String;"), "V")))
        di.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, 0, ImmutableStringReference(scheme.transform)))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, ImmutableMethodReference("Ljavax/crypto/Cipher;", "getInstance", listOf("Ljava/lang/String;"), "Ljavax/crypto/Cipher;")))
        di.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0))
        di.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 3, 2))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 3, 0, 3, 2, 0, 0, ImmutableMethodReference("Ljavax/crypto/Cipher;", "init", listOf("I", "Ljava/security/Key;"), "V")))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, 0, 1, 0, 0, 0, ImmutableMethodReference("Ljavax/crypto/Cipher;", "doFinal", listOf("[B"), "[B")))
        di.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1))
        di.addInstruction(BuilderInstruction21c(Opcode.NEW_INSTANCE, 2, ImmutableTypeReference("Ljava/lang/String;")))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_DIRECT, 2, 2, 1, 0, 0, 0, strInit))
        di.addInstruction(BuilderInstruction11x(Opcode.RETURN_OBJECT, 2))

        return ImmutableClassDef(
            ct, AccessFlags.PUBLIC.value, "Ljava/lang/Object;",
            emptyList(), null, ImmutableSet.of(), listOf(kf), emptyList(),
            listOf(
                ImmutableMethod(ct, "<clinit>", emptyList(), "V", AccessFlags.STATIC.value or AccessFlags.CONSTRUCTOR.value, ImmutableSet.of(), ImmutableSet.of(), ci),
                ImmutableMethod(ct, "decrypt", listOf(ImmutableMethodParameter("Ljava/lang/String;", ImmutableSet.of(), null)), "Ljava/lang/String;", AccessFlags.PUBLIC.value or AccessFlags.STATIC.value, ImmutableSet.of(), ImmutableSet.of(), di)
            ), emptyList()
        )
    }

    private fun createDexRewriter(scheme: EncScheme, stringIndexMap: Map<String, Int>): DexRewriter {
        return DexRewriter(object : RewriterModule() {
            override fun getClassDefRewriter(rewriters: Rewriters): Rewriter<ClassDef> {
                val r = super.getClassDefRewriter(rewriters)
                return Rewriter { classDef ->
                    if (classDef.type == "Lcom/secure/Decryptor;" || classDef.type == "Lcom/secure/StringPool;") {
                        classDef
                    } else {
                        r.rewrite(classDef)
                    }
                }
            }

            override fun getMethodImplementationRewriter(rewriters: Rewriters): Rewriter<MethodImplementation> {
                return Rewriter { impl ->
                    try {
                        val m = MutableMethodImplementation(impl)
                        val ins = m.instructions
                        var i = 0
                        while (i < ins.size) {
                            val inst = ins[i]
                            if (inst is ReferenceInstruction && inst.reference is StringReference) {
                                if (i + 1 < ins.size) {
                                    val next = ins[i + 1]
                                    if (next is ReferenceInstruction && next.reference is ImmutableMethodReference) {
                                        val ref = next.reference as ImmutableMethodReference
                                        if (ref.definingClass == "Lcom/secure/Decryptor;" && ref.name == "decrypt") {
                                            i++
                                            continue
                                        }
                                    }
                                }
                                val str = (inst.reference as StringReference).string
                                val reg = if (inst is OneRegisterInstruction) inst.registerA else -1
                                if (reg >= 0) {
                                    if (stringIndexMap.containsKey(str)) {
                                        val idx = stringIndexMap[str]!!
                                        if (idx in -8..7) {
                                            m.replaceInstruction(i, BuilderInstruction11n(Opcode.CONST_4, reg, idx))
                                        } else if (idx in Short.MIN_VALUE..Short.MAX_VALUE) {
                                            m.replaceInstruction(i, BuilderInstruction21s(Opcode.CONST_16, reg, idx))
                                        } else {
                                            m.replaceInstruction(i, BuilderInstruction31i(Opcode.CONST, reg, idx))
                                        }
                                        val poolRef = ImmutableMethodReference("Lcom/secure/StringPool;", "get", listOf("I"), "Ljava/lang/String;")
                                        if (reg < 16) {
                                            m.addInstruction(i + 1, BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, reg, 0, 0, 0, 0, poolRef))
                                        } else {
                                            m.addInstruction(i + 1, BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, reg, 1, poolRef))
                                        }
                                        m.addInstruction(i + 2, BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, reg))
                                        i += 2
                                    } else {
                                        val enc = encryptPayload(str, scheme)
                                        m.replaceInstruction(i, BuilderInstruction21c(Opcode.CONST_STRING, reg, ImmutableStringReference(enc)))
                                        val decRef = ImmutableMethodReference("Lcom/secure/Decryptor;", "decrypt", listOf("Ljava/lang/String;"), "Ljava/lang/String;")
                                        if (reg < 16) {
                                            m.addInstruction(i + 1, BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, reg, 0, 0, 0, 0, decRef))
                                        } else {
                                            m.addInstruction(i + 1, BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, reg, 1, decRef))
                                        }
                                        m.addInstruction(i + 2, BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, reg))
                                        i += 2
                                    }
                                }
                            }
                            i++
                        }
                        m
                    } catch (e: Exception) {
                        impl
                    }
                }
            }
        })
    }

    /**
     * 重新打包 APK。
     *
     * 两趟写：
     *  1) 正常写出并对齐（resources.arsc 强制 STORED + 4 字节对齐，.so 按 4096）；
     *  2) 回读产物自检 resources.arsc 的数据区偏移，若没落在 4 字节边界上，
     *     给第一个条目多塞 4+shift 字节的 extra 把后面整体后移 shift 字节，再写一遍。
     *
     * 这样无论 JDK 写本地头时怎么处理 extra，最终产物都是对齐的。
     */
    private fun repackApk(originalApk: File, modifiedDexMap: Map<String, ByteArray>, outputApk: File) {
        val arscLocOffset = writeRepackedApk(originalApk, modifiedDexMap, outputApk, 0)
        val shift = resourcesArscShiftNeeded(outputApk, arscLocOffset)
        if (shift > 0) {
            writeRepackedApk(originalApk, modifiedDexMap, outputApk, shift)
        }
    }

    /** 写一趟，返回 resources.arsc 本地头偏移（没找到则 -1） */
    private fun writeRepackedApk(
        originalApk: File,
        modifiedDexMap: Map<String, ByteArray>,
        outputApk: File,
        globalShift: Int
    ): Long {
        var arscLocOffset = -1L
        var shiftPending = globalShift > 0
        ZipFile(originalApk).use { zip ->
            // 注意：这里不能再套 BufferedOutputStream——对齐计算依赖 counter.count
            // 精确等于「下一个本地文件头的起始偏移」，缓冲会让计数滞后。
            CountingOutputStream(FileOutputStream(outputApk)).use { counter ->
                ZipOutputStream(counter).use { zos ->
                    val entries = zip.entries()
                    while (entries.hasMoreElements()) {
                        val e = entries.nextElement()
                        // 被替换的 dex 跳过（稍后统一写入）
                        if (modifiedDexMap.containsKey(e.name)) continue
                        // 改动后的 APK 原签名必然失效，丢掉旧签名文件，交给用户重新签名
                        if (isSignatureFile(e.name)) continue

                        // 需要整体后移：塞在第一个写出的条目上，它后面所有偏移一起挪
                        val prePad: ByteArray? = if (shiftPending) {
                            shiftPending = false
                            paddingExtra(4 + globalShift)
                        } else null

                        val ne = ZipEntry(e.name)
                        ne.time = e.time
                        if (e.isDirectory) {
                            ne.extra = prePad
                            zos.putNextEntry(ne)
                            zos.closeEntry()
                            continue
                        }

                        // Android 11 +：resources.arsc 必须 STORED。
                        // 源里就算是被压过的，也要掰回来，否则装不上：
                        // "Targeting R+ requires the resources.arsc ... to be stored uncompressed"
                        val mustStore = e.name == "resources.arsc"
                        if (e.method == ZipEntry.STORED || mustStore) {
                            ne.method = ZipEntry.STORED
                            ne.size = e.size
                            ne.compressedSize = e.size
                            ne.crc = e.crc
                            val align = if (e.name.endsWith(".so")) 4096 else 4
                            ne.extra = mergeExtra(
                                prePad,
                                alignmentExtra(counter.count, e.name, align, prePad?.size ?: 0)
                            )
                            if (mustStore) arscLocOffset = counter.count
                            zos.putNextEntry(ne)
                            zip.getInputStream(e).use { it.copyTo(zos) }
                        } else {
                            ne.extra = prePad
                            zos.putNextEntry(ne)
                            zip.getInputStream(e).use { it.copyTo(zos) }
                        }
                        zos.closeEntry()
                    }

                    // 写入加密后的 dex（DEX 允许压缩，保持 DEFLATED 以减小体积）
                    for ((name, bytes) in modifiedDexMap) {
                        val de = ZipEntry(name)
                        zos.putNextEntry(de)
                        zos.write(bytes)
                        zos.closeEntry()
                    }
                }
            }
        }
        return arscLocOffset
    }

    /**
     * 回读产物自检：resources.arsc 的数据区是否落在 4 字节边界上。
     * 返回需要整体后移的字节数（0 = 已经对齐，或压根查不到）。
     */
    private fun resourcesArscShiftNeeded(apk: File, locOffset: Long): Int {
        if (locOffset < 0) return 0
        var shift = 0
        try {
            java.io.RandomAccessFile(apk, "r").use { raf ->
                val header = ByteArray(30)
                raf.seek(locOffset)
                raf.readFully(header)
                // 本地头签名 0x04034b50，压缩方式字段为 0 才算 STORED
                if (le32(header, 0) == 0x04034b50L && le16(header, 8) == 0) {
                    val nameLen = le16(header, 26)
                    val extraLen = le16(header, 28)
                    val dataOffset = locOffset + 30L + nameLen + extraLen
                    shift = ((4 - (dataOffset % 4)) % 4).toInt()
                }
            }
        } catch (_: Exception) {
            shift = 0
        }
        return shift
    }

    private fun le16(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or ((b[off + 1].toInt() and 0xFF) shl 8)

    private fun le32(b: ByteArray, off: Int): Long =
        ((b[off].toInt() and 0xFF).toLong()) or
            ((b[off + 1].toInt() and 0xFF).toLong() shl 8) or
            ((b[off + 2].toInt() and 0xFF).toLong() shl 16) or
            ((b[off + 3].toInt() and 0xFF).toLong() shl 24)

    /** 旧 v1 签名文件：内容被改动后必然校验失败，直接剔除 */
    private fun isSignatureFile(name: String): Boolean {
        if (!name.startsWith("META-INF/")) return false
        val upper = name.uppercase()
        return upper.endsWith(".SF") || upper.endsWith(".RSA") ||
            upper.endsWith(".DSA") || upper.endsWith(".EC") ||
            upper == "META-INF/MANIFEST.MF"
    }

    /**
     * 计算让 entry 数据区起始位置对齐到 align 的 extra 字段。
     *
     * 数据区偏移 = headerOffset + 30(本地头) + nameLen + prePad + extraLen，
     * 本地文件头固定 30 字节（4 签名 + 2 版本 + 2 标志 + 2 方法 + 4 时间
     * + 4 crc + 4 压缩后大小 + 4 原始大小 + 2 名字长 + 2 extra 长），
     * 后面紧跟 name 和 extra，所以数据区偏移就是上面这个式子。
     *
     * extra 字段要么为空，要么至少 4 字节（2 字节 id + 2 字节长度），
     * 而且 extraLen 本身参与偏移计算，所以必须按 extraLen 反解：
     * 从小到大找第一个满足 (base + extraLen) % align == 0 且 extraLen == 0 或 >= 4 的值。
     */
    private fun alignmentExtra(headerOffset: Long, name: String, align: Int, prePad: Int): ByteArray? {
        val nameLen = name.toByteArray(Charsets.UTF_8).size
        val base = headerOffset + 30 + nameLen + prePad
        // 上限要留出一个完整对齐周期的余量：最小的合法 extraLen 可能落在
        // [4, align+3] 区间内（例如 base%4==2 时合法值是 2,6,10...，要取 6）。
        var extraLen = 0
        while (extraLen <= align + 4) {
            if ((base + extraLen) % align == 0L) {
                if (extraLen == 0) return null
                if (extraLen >= 4) return paddingExtra(extraLen)
            }
            extraLen++
        }
        return null
    }

    /**
     * 造一个长度恰好为 len（>=4）的合法 extra 子字段，只用来占位撑偏移。
     * 结构：2 字节 id(0x35D9) + 2 字节数据长 + N 字节 0。
     */
    private fun paddingExtra(len: Int): ByteArray {
        val n = if (len < 4) 4 else len
        val extra = ByteArray(n)
        extra[0] = 0xD9.toByte()
        extra[1] = 0x35.toByte()
        val payload = n - 4
        extra[2] = (payload and 0xFF).toByte()
        extra[3] = ((payload shr 8) and 0xFF).toByte()
        return extra
    }

    /** 拼两个 extra 字段（各自都是合法子字段序列，直接首尾相接即可） */
    private fun mergeExtra(a: ByteArray?, b: ByteArray?): ByteArray? = when {
        a == null || a.isEmpty() -> b
        b == null || b.isEmpty() -> a
        else -> a + b
    }

    companion object {
        private const val MAX_POOL_STRINGS = 2000

        // 抽屉弹出抽查动画！！！噢齁齁齁齁齁齁
        private const val DRAWER_DURATION_MS = 300L
        private const val DRAWER_DECELERATE_FACTOR = 1.0f

        // 配置弹窗进场 / 退场节奏
        private const val OVERLAY_SCRIM_MS = 200L
        private const val OVERLAY_CARD_MS = 260L
        private const val OVERLAY_EXIT_MS = 160L

        private val METHOD_LABELS = mapOf(
            "Base64" to "Base64（仅编码混淆）",
            "AES" to "AES（对称加密，推荐）",
            "DES" to "DES（轻量对称加密）",
            "RC4" to "RC4（流加密，速度快）"
        )
        private val STRENGTH_LABELS = mapOf(
            "low" to "低",
            "medium" to "中",
            "high" to "高"
        )
        private val STRENGTH_TEXTS = mapOf(
            "low" to "低（128 位密钥）",
            "medium" to "中（192 位密钥）",
            "high" to "高（256 位密钥）"
        )
    }

    private class CountingOutputStream(out: java.io.OutputStream) : java.io.FilterOutputStream(out) {
        var count: Long = 0L
            private set

        override fun write(b: Int) {
            out.write(b)
            count++
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            out.write(b, off, len)
            count += len
        }
    }
}
