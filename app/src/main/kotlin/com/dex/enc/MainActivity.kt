package com.dex.enc

import android.widget.Switch
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
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
import android.view.Gravity
import android.view.View
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
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom

class MainActivity : AppCompatActivity() {

    private lateinit var etPath: EditText
// private lateinit var rgMode: RadioGroup
// private lateinit var rbNormal: RadioButton
// private lateinit var rbAdvanced: RadioButton
private lateinit var swNormal: Switch
private lateinit var swAdvanced: Switch
private lateinit var swSuper: Switch
private val superEncryptKey = SecretKeySpec("MySuperKey1234567".toByteArray(), "AES")
private val secureRandom = SecureRandom()
    private var selectedApkUri: Uri? = null
    private var selectedFileName: String? = null
    private val encryptKey = SecretKeySpec("MySecureKey12345".toByteArray(), "AES")
    private val handler = Handler(Looper.getMainLooper())

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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
etPath = findViewById(R.id.et_path)
swNormal = findViewById(R.id.sw_normal)
swAdvanced = findViewById(R.id.sw_advanced)
swSuper = findViewById(R.id.sw_super)
// 原来的 rgMode、rbNormal、rbAdvanced 这三行删除或注释掉

        findViewById<ImageView>(R.id.iv_choose).setOnClickListener {
            openDocumentLauncher.launch("*/*")
        }

findViewById<ImageView>(R.id.iv_start).setOnClickListener {
    if (selectedApkUri == null) {
        Toast.makeText(this, "请先选择文件", Toast.LENGTH_SHORT).show()
        return@setOnClickListener
    }
val normalOn = swNormal.isChecked
val advancedOn = swAdvanced.isChecked
val superOn = swSuper.isChecked

val activeCount = listOf(normalOn, advancedOn, superOn).count { it }

if (activeCount == 0) {
    Toast.makeText(this, "请至少开启一个加密模式", Toast.LENGTH_SHORT).show()
    return@setOnClickListener
}

if (activeCount > 1) {
    Toast.makeText(this, "请只开启一个加密模式", Toast.LENGTH_SHORT).show()
    return@setOnClickListener
}

val mode = when {
    normalOn -> "normal"
    advancedOn -> "advanced"
    else -> "super"
}
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
            handler.post { showEncryptDialog(cacheFile, mode) }
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

private fun showEncryptDialog(inputApk: File, mode: String) {
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
        doEncrypt(dialog, inputApk, selectedDex, mode, llLoading, tvStatus, tvSuccess, btnCopy, btnDismiss)
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
        mode: String,
        llLoading: LinearLayout,
        tvStatus: TextView,
        tvSuccess: TextView,
        btnCopy: TextView,
        btnDismiss: TextView
    ) {
        Thread {
            try {
                val modifiedDexMap = mutableMapOf<String, ByteArray>()
                for ((index, dexName) in selectedDex.withIndex()) {
                    handler.post {
                        tvStatus.text = "正在加密 $dexName (${index + 1}/${selectedDex.size})..."
                    }
                    val originalBytes: ByteArray
                    if (inputApk.extension.equals("dex", true)) {
                        originalBytes = inputApk.readBytes()
                    } else {
                        originalBytes = ZipFile(inputApk).use {
                            it.getInputStream(it.getEntry(dexName)!!).readBytes()
                        }
                    }
                    modifiedDexMap[dexName] = processSingleDex(
                        originalBytes,
                        index == 0,
                        mode,
                        emptyMap()
                    )
                    handler.post {
                        tvStatus.text = "$dexName 加密成功 (${index + 1}/${selectedDex.size})"
                    }
                }

                if (inputApk.extension.equals("dex", true)) {
                    // 单独DEX：直接输出，不显示"请签名"
                    val outputDex = File(getSafeOutputDirectory(), "enc_${inputApk.name}")
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
                    val outputApk = File(getSafeOutputDirectory(), "enc_${inputApk.name}")
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

    private fun getSafeOutputDirectory(): File {
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
        mode: String,
        stringIndexMap: Map<String, Int>
    ): ByteArray {
        val tempIn = File(cacheDir, "temp_in.dex")
        tempIn.writeBytes(dexBytes)
        val opcodes = Opcodes.getDefault()
        val originalDex = DexFileFactory.loadDexFile(tempIn, opcodes)

        val effectiveStringIndexMap = if (mode == "super") {
            collectStrings(dexBytes)
        } else {
            stringIndexMap
        }

        val rewrittenDex = createDexRewriter(mode, effectiveStringIndexMap).getDexFileRewriter().rewrite(originalDex)
        val allClasses = rewrittenDex.classes.mapTo(mutableSetOf<ClassDef>()) { it }
        if (injectDecryptor) {
            if (mode == "super") {
                allClasses.add(buildSuperDecryptorClass())
                allClasses.add(buildSuperStringPoolClass(effectiveStringIndexMap))
                allClasses.add(buildJunkClass("Lcom/secure/a/Helper;"))
                allClasses.add(buildJunkClass("Lcom/secure/b/Processor;"))
                allClasses.add(buildJunkClass("Lcom/secure/c/Handler;"))
            } else {
                allClasses.add(buildDecryptorClass())
                if (mode == "advanced") {
                    allClasses.add(buildStringPoolClass(stringIndexMap))
                }
            }
        }
        val tempOut = File(cacheDir, "temp_out.dex")
        DexFileFactory.writeDexFile(tempOut.absolutePath, ImmutableDexFile(opcodes, allClasses))
        val result = tempOut.readBytes()
        tempIn.delete()
        tempOut.delete()
        return result
    }

    private fun buildStringPoolClass(stringIndexMap: Map<String, Int>): ClassDef {
        val classType = "Lcom/secure/StringPool;"
        val encStrings = stringIndexMap.keys.map { str ->
            try {
                val c = Cipher.getInstance("AES/ECB/PKCS5Padding")
                c.init(Cipher.ENCRYPT_MODE, encryptKey)
                Base64.encodeToString(c.doFinal(str.toByteArray()), Base64.NO_WRAP)
            } catch (e: Exception) {
                str
            }
        }
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

    private fun buildDecryptorClass(): ClassDef {
        val ct = "Lcom/secure/Decryptor;"
        val kf = ImmutableField(ct, "key", "[B", AccessFlags.PRIVATE.value or AccessFlags.STATIC.value, null, ImmutableSet.of(), ImmutableSet.of())

        val ci = MutableMethodImplementation(2)
        ci.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, 0, ImmutableStringReference("MySecureKey12345")))
        ci.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0, ImmutableMethodReference("Ljava/lang/String;", "getBytes", emptyList(), "[B")))
        ci.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1))
        ci.addInstruction(BuilderInstruction21c(Opcode.SPUT_OBJECT, 1, kf))
        ci.addInstruction(BuilderInstruction10x(Opcode.RETURN_VOID))

        val di = MutableMethodImplementation(5)
        di.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 0, 0))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 4, 0, 0, 0, 0, ImmutableMethodReference("Landroid/util/Base64;", "decode", listOf("Ljava/lang/String;", "I"), "[B")))
        di.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1))
        di.addInstruction(BuilderInstruction21c(Opcode.NEW_INSTANCE, 2, ImmutableTypeReference("Ljavax/crypto/spec/SecretKeySpec;")))
        di.addInstruction(BuilderInstruction21c(Opcode.SGET_OBJECT, 0, kf))
        di.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, 3, ImmutableStringReference("AES")))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_DIRECT, 3, 2, 0, 3, 0, 0, ImmutableMethodReference("Ljavax/crypto/spec/SecretKeySpec;", "<init>", listOf("[B", "Ljava/lang/String;"), "V")))
        di.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, 0, ImmutableStringReference("AES/ECB/PKCS5Padding")))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, ImmutableMethodReference("Ljavax/crypto/Cipher;", "getInstance", listOf("Ljava/lang/String;"), "Ljavax/crypto/Cipher;")))
        di.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0))
        di.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 3, 2))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 3, 0, 3, 2, 0, 0, ImmutableMethodReference("Ljavax/crypto/Cipher;", "init", listOf("I", "Ljava/security/Key;"), "V")))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, 0, 1, 0, 0, 0, ImmutableMethodReference("Ljavax/crypto/Cipher;", "doFinal", listOf("[B"), "[B")))
        di.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1))
        di.addInstruction(BuilderInstruction21c(Opcode.NEW_INSTANCE, 2, ImmutableTypeReference("Ljava/lang/String;")))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_DIRECT, 2, 2, 1, 0, 0, 0, ImmutableMethodReference("Ljava/lang/String;", "<init>", listOf("[B"), "V")))
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

    private fun createDexRewriter(mode: String, stringIndexMap: Map<String, Int>): DexRewriter {
        return DexRewriter(object : RewriterModule() {
            override fun getClassDefRewriter(rewriters: Rewriters): Rewriter<ClassDef> {
                val r = super.getClassDefRewriter(rewriters)
                return Rewriter { classDef ->
                    if (classDef.type == "Lcom/secure/Decryptor;" || classDef.type == "Lcom/secure/StringPool;" || classDef.type == "Lcom/secure/SuperDecryptor;" || classDef.type == "Lcom/secure/SuperStringPool;" || classDef.type.startsWith("Lcom/secure/a/") || classDef.type.startsWith("Lcom/secure/b/") || classDef.type.startsWith("Lcom/secure/c/")) {
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
                                        if ((ref.definingClass == "Lcom/secure/Decryptor;" || ref.definingClass == "Lcom/secure/SuperDecryptor;") && ref.name == "decrypt") {
                                            i++
                                            continue
                                        }
                                    }
                                }
                                val str = (inst.reference as StringReference).string
                                val reg = if (inst is OneRegisterInstruction) inst.registerA else -1
                                if (reg >= 0) {
                                    if ((mode == "advanced" || mode == "super") && stringIndexMap.containsKey(str)) {
                                        val idx = stringIndexMap[str]!!
                                        if (idx in -8..7) {
                                            m.replaceInstruction(i, BuilderInstruction11n(Opcode.CONST_4, reg, idx))
                                        } else if (idx in Short.MIN_VALUE..Short.MAX_VALUE) {
                                            m.replaceInstruction(i, BuilderInstruction21s(Opcode.CONST_16, reg, idx))
                                        } else {
                                            m.replaceInstruction(i, BuilderInstruction31i(Opcode.CONST, reg, idx))
                                        }
                                        val poolRef = if (mode == "super") {
                                            ImmutableMethodReference("Lcom/secure/SuperStringPool;", "get", listOf("I"), "Ljava/lang/String;")
                                        } else {
                                            ImmutableMethodReference("Lcom/secure/StringPool;", "get", listOf("I"), "Ljava/lang/String;")
                                        }
                                        if (reg < 16) {
                                            m.addInstruction(i + 1, BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, reg, 0, 0, 0, 0, poolRef))
                                        } else {
                                            m.addInstruction(i + 1, BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, reg, 1, poolRef))
                                        }
                                        m.addInstruction(i + 2, BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, reg))
                                        i += 2
                                    } else {
                                        val enc = if (mode == "super") {
                                            superEncryptString(str)
                                        } else {
                                            try {
                                                val c = Cipher.getInstance("AES/ECB/PKCS5Padding")
                                                c.init(Cipher.ENCRYPT_MODE, encryptKey)
                                                Base64.encodeToString(c.doFinal(str.toByteArray()), Base64.NO_WRAP)
                                            } catch (e: Exception) {
                                                str
                                            }
                                        }
                                        m.replaceInstruction(i, BuilderInstruction21c(Opcode.CONST_STRING, reg, ImmutableStringReference(enc)))
                                        val decRef = if (mode == "super") {
                                            ImmutableMethodReference("Lcom/secure/SuperDecryptor;", "decrypt", listOf("Ljava/lang/String;"), "Ljava/lang/String;")
                                        } else {
                                            ImmutableMethodReference("Lcom/secure/Decryptor;", "decrypt", listOf("Ljava/lang/String;"), "Ljava/lang/String;")
                                        }
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

    private fun collectStrings(dexBytes: ByteArray): Map<String, Int> {
        val tempFile = File(cacheDir, "temp_scan.dex")
        tempFile.writeBytes(dexBytes)
        val dex = DexFileFactory.loadDexFile(tempFile, Opcodes.getDefault())
        val stringSet = mutableSetOf<String>()
        for (classDef in dex.classes) {
            if (classDef.type.startsWith("Lcom/secure/")) continue
            for (method in classDef.methods) {
                val impl = method.implementation ?: continue
                for (inst in impl.instructions) {
                    if (inst is ReferenceInstruction && inst.reference is StringReference) {
                        val str = (inst.reference as StringReference).string
                        if (str.isNotEmpty()) {
                            stringSet.add(str)
                        }
                    }
                }
            }
        }
        tempFile.delete()
        val shuffled = stringSet.toList().shuffled(secureRandom)
        return shuffled.mapIndexed { index, s -> s to index }.toMap()
    }

    private fun superEncryptString(str: String): String {
        val iv = ByteArray(16)
        secureRandom.nextBytes(iv)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, superEncryptKey, IvParameterSpec(iv))
        val encrypted = cipher.doFinal(str.toByteArray())
        val combined = ByteArray(iv.size + encrypted.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encrypted, 0, combined, iv.size, encrypted.size)
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    private fun buildSuperDecryptorClass(): ClassDef {
        val ct = "Lcom/secure/SuperDecryptor;"
        val kf = ImmutableField(ct, "key", "[B", AccessFlags.PRIVATE.value or AccessFlags.STATIC.value, null, ImmutableSet.of(), ImmutableSet.of())

        val ci = MutableMethodImplementation(4)
        ci.addInstruction(BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, ImmutableMethodReference("Landroid/os/Debug;", "isDebuggerConnected", emptyList(), "Z")))
        ci.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT, 0))
        ci.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, 1, ImmutableStringReference("MySuperKey1234567")))
        ci.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 1, 0, 0, 0, 0, ImmutableMethodReference("Ljava/lang/String;", "getBytes", emptyList(), "[B")))
        ci.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1))
        ci.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 2, 1))
        ci.addInstruction(BuilderInstruction23x(Opcode.SUB_INT, 0, 2, 0))
        ci.addInstruction(BuilderInstruction12x(Opcode.ARRAY_LENGTH, 2, 1))
        ci.addInstruction(BuilderInstruction23x(Opcode.MUL_INT, 2, 2, 0))
        ci.addInstruction(BuilderInstruction22c(Opcode.NEW_ARRAY, 0, 2, ImmutableTypeReference("[B")))
        ci.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 3, 0))
        ci.addInstruction(BuilderInstruction35c(Opcode.INVOKE_STATIC, 5, 1, 3, 0, 3, 2, ImmutableMethodReference("Ljava/lang/System;", "arraycopy", listOf("Ljava/lang/Object;", "I", "Ljava/lang/Object;", "I", "I"), "V")))
        ci.addInstruction(BuilderInstruction21c(Opcode.SPUT_OBJECT, 0, kf))
        ci.addInstruction(BuilderInstruction10x(Opcode.RETURN_VOID))

        val di = MutableMethodImplementation(12)
        di.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 0, 0))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 11, 0, 0, 0, 0, ImmutableMethodReference("Landroid/util/Base64;", "decode", listOf("Ljava/lang/String;", "I"), "[B")))
        di.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0))
        di.addInstruction(BuilderInstruction21s(Opcode.CONST_16, 1, 16))
        di.addInstruction(BuilderInstruction22c(Opcode.NEW_ARRAY, 2, 1, ImmutableTypeReference("[B")))
        di.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 3, 0))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_STATIC, 5, 0, 3, 2, 3, 1, ImmutableMethodReference("Ljava/lang/System;", "arraycopy", listOf("Ljava/lang/Object;", "I", "Ljava/lang/Object;", "I", "I"), "V")))
        di.addInstruction(BuilderInstruction12x(Opcode.ARRAY_LENGTH, 1, 0))
        di.addInstruction(BuilderInstruction21s(Opcode.CONST_16, 3, 16))
        di.addInstruction(BuilderInstruction23x(Opcode.SUB_INT, 1, 1, 3))
        di.addInstruction(BuilderInstruction22c(Opcode.NEW_ARRAY, 3, 1, ImmutableTypeReference("[B")))
        di.addInstruction(BuilderInstruction21s(Opcode.CONST_16, 4, 16))
        di.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 5, 0))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_STATIC, 5, 0, 4, 3, 5, 1, ImmutableMethodReference("Ljava/lang/System;", "arraycopy", listOf("Ljava/lang/Object;", "I", "Ljava/lang/Object;", "I", "I"), "V")))
        di.addInstruction(BuilderInstruction21c(Opcode.NEW_INSTANCE, 4, ImmutableTypeReference("Ljavax/crypto/spec/SecretKeySpec;")))
        di.addInstruction(BuilderInstruction21c(Opcode.SGET_OBJECT, 5, kf))
        di.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, 6, ImmutableStringReference("AES")))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_DIRECT, 3, 4, 5, 6, 0, 0, ImmutableMethodReference("Ljavax/crypto/spec/SecretKeySpec;", "<init>", listOf("[B", "Ljava/lang/String;"), "V")))
        di.addInstruction(BuilderInstruction21c(Opcode.NEW_INSTANCE, 5, ImmutableTypeReference("Ljavax/crypto/spec/IvParameterSpec;")))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_DIRECT, 2, 5, 2, 0, 0, 0, ImmutableMethodReference("Ljavax/crypto/spec/IvParameterSpec;", "<init>", listOf("[B"), "V")))
        di.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, 6, ImmutableStringReference("AES/CBC/PKCS5Padding")))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 6, 0, 0, 0, 0, ImmutableMethodReference("Ljavax/crypto/Cipher;", "getInstance", listOf("Ljava/lang/String;"), "Ljavax/crypto/Cipher;")))
        di.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 6))
        di.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 7, 2))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 4, 6, 7, 4, 5, 0, ImmutableMethodReference("Ljavax/crypto/Cipher;", "init", listOf("I", "Ljava/security/Key;", "Ljava/security/spec/AlgorithmParameterSpec;"), "V")))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, 6, 3, 0, 0, 0, ImmutableMethodReference("Ljavax/crypto/Cipher;", "doFinal", listOf("[B"), "[B")))
        di.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 3))
        di.addInstruction(BuilderInstruction21c(Opcode.NEW_INSTANCE, 4, ImmutableTypeReference("Ljava/lang/String;")))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_DIRECT, 2, 4, 3, 0, 0, 0, ImmutableMethodReference("Ljava/lang/String;", "<init>", listOf("[B"), "V")))
        di.addInstruction(BuilderInstruction11x(Opcode.RETURN_OBJECT, 4))

        return ImmutableClassDef(
            ct, AccessFlags.PUBLIC.value, "Ljava/lang/Object;",
            emptyList(), null, ImmutableSet.of(), listOf(kf), emptyList(),
            listOf(
                ImmutableMethod(ct, "<clinit>", emptyList(), "V", AccessFlags.STATIC.value or AccessFlags.CONSTRUCTOR.value, ImmutableSet.of(), ImmutableSet.of(), ci),
                ImmutableMethod(ct, "decrypt", listOf(ImmutableMethodParameter("Ljava/lang/String;", ImmutableSet.of(), null)), "Ljava/lang/String;", AccessFlags.PUBLIC.value or AccessFlags.STATIC.value, ImmutableSet.of(), ImmutableSet.of(), di)
            ), emptyList()
        )
    }

    private fun buildSuperStringPoolClass(stringIndexMap: Map<String, Int>): ClassDef {
        val classType = "Lcom/secure/SuperStringPool;"
        val maxIndex = stringIndexMap.values.maxOrNull() ?: -1
        val encStrings = Array(maxIndex + 1) { "" }
        for ((str, idx) in stringIndexMap) {
            encStrings[idx] = try {
                superEncryptString(str)
            } catch (e: Exception) {
                str
            }
        }
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
                ImmutableMethodReference("Lcom/secure/SuperDecryptor;", "decrypt", listOf("Ljava/lang/String;"), "Ljava/lang/String;")
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

    private fun buildJunkClass(classType: String): ClassDef {
        val tagField = ImmutableField(
            classType, "tag", "I",
            AccessFlags.PRIVATE.value or AccessFlags.STATIC.value,
            null, ImmutableSet.of(), ImmutableSet.of()
        )
        val dataField = ImmutableField(
            classType, "data", "[B",
            AccessFlags.PRIVATE.value or AccessFlags.STATIC.value,
            null, ImmutableSet.of(), ImmutableSet.of()
        )

        val clinit = MutableMethodImplementation(3)
        clinit.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 0, 7))
        clinit.addInstruction(BuilderInstruction21c(Opcode.SPUT, 0, tagField))
        clinit.addInstruction(BuilderInstruction21s(Opcode.CONST_16, 0, 64))
        clinit.addInstruction(BuilderInstruction22c(Opcode.NEW_ARRAY, 1, 0, ImmutableTypeReference("[B")))
        clinit.addInstruction(BuilderInstruction21c(Opcode.SPUT_OBJECT, 1, dataField))
        clinit.addInstruction(BuilderInstruction10x(Opcode.RETURN_VOID))

        val compute = MutableMethodImplementation(4)
        compute.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 1, 3))
        compute.addInstruction(BuilderInstruction23x(Opcode.MUL_INT, 0, 3, 1))
        compute.addInstruction(BuilderInstruction21s(Opcode.CONST_16, 1, 17))
        compute.addInstruction(BuilderInstruction23x(Opcode.ADD_INT, 0, 0, 1))
        compute.addInstruction(BuilderInstruction21c(Opcode.SGET, 2, tagField))
        compute.addInstruction(BuilderInstruction23x(Opcode.ADD_INT, 0, 0, 2))
        compute.addInstruction(BuilderInstruction11x(Opcode.RETURN, 0))

        val process = MutableMethodImplementation(4)
        process.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 3, 0, 0, 0, 0,
            ImmutableMethodReference("Ljava/lang/String;", "length", emptyList(), "I")))
        process.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT, 0))
        process.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 1, 1))
        process.addInstruction(BuilderInstruction23x(Opcode.ADD_INT, 0, 0, 1))
        process.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, 3, 0, 0, 0, 0,
            ImmutableMethodReference("Ljava/lang/String;", "substring", listOf("I", "I"), "Ljava/lang/String;")))
        process.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0))
        process.addInstruction(BuilderInstruction11x(Opcode.RETURN_OBJECT, 0))

        val transform = MutableMethodImplementation(3)
        transform.addInstruction(BuilderInstruction21c(Opcode.SGET_OBJECT, 0, dataField))
        transform.addInstruction(BuilderInstruction12x(Opcode.ARRAY_LENGTH, 1, 0))
        transform.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 2, 1))
        transform.addInstruction(BuilderInstruction23x(Opcode.SUB_INT, 1, 1, 2))
        transform.addInstruction(BuilderInstruction11x(Opcode.RETURN, 1))

        return ImmutableClassDef(
            classType, AccessFlags.PUBLIC.value, "Ljava/lang/Object;",
            emptyList(), null, ImmutableSet.of(), listOf(tagField, dataField), emptyList(),
            listOf(
                ImmutableMethod(classType, "<clinit>", emptyList(), "V",
                    AccessFlags.STATIC.value or AccessFlags.CONSTRUCTOR.value,
                    ImmutableSet.of(), ImmutableSet.of(), clinit),
                ImmutableMethod(classType, "compute", listOf(ImmutableMethodParameter("I", ImmutableSet.of(), null)), "I",
                    AccessFlags.PUBLIC.value or AccessFlags.STATIC.value,
                    ImmutableSet.of(), ImmutableSet.of(), compute),
                ImmutableMethod(classType, "process", listOf(ImmutableMethodParameter("Ljava/lang/String;", ImmutableSet.of(), null)), "Ljava/lang/String;",
                    AccessFlags.PUBLIC.value or AccessFlags.STATIC.value,
                    ImmutableSet.of(), ImmutableSet.of(), process),
                ImmutableMethod(classType, "transform", emptyList(), "I",
                    AccessFlags.PUBLIC.value or AccessFlags.STATIC.value,
                    ImmutableSet.of(), ImmutableSet.of(), transform)
            ), emptyList()
        )
    }

    private fun repackApk(originalApk: File, modifiedDexMap: Map<String, ByteArray>, outputApk: File) {
        ZipOutputStream(FileOutputStream(outputApk)).use { zos ->
            ZipFile(originalApk).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val e = entries.nextElement()
                    if (!modifiedDexMap.containsKey(e.name)) {
                        zos.putNextEntry(ZipEntry(e.name))
                        zip.getInputStream(e).use { it.copyTo(zos) }
                        zos.closeEntry()
                    }
                }
            }
            for ((name, bytes) in modifiedDexMap) {
                zos.putNextEntry(ZipEntry(name))
                zos.write(bytes)
                zos.closeEntry()
            }
        }
    }
}
