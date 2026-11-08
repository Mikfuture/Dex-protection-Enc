package com.dex.enc

import com.google.common.collect.ImmutableSet
import org.jf.dexlib2.AccessFlags
import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcode
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.builder.BuilderInstruction
import org.jf.dexlib2.builder.BuilderOffsetInstruction
import org.jf.dexlib2.builder.Label
import org.jf.dexlib2.builder.MutableMethodImplementation
import org.jf.dexlib2.builder.instruction.*
import org.jf.dexlib2.iface.ClassDef
import org.jf.dexlib2.iface.DexFile
import org.jf.dexlib2.iface.Method
import org.jf.dexlib2.iface.instruction.OneRegisterInstruction
import org.jf.dexlib2.iface.instruction.ReferenceInstruction
import org.jf.dexlib2.iface.reference.StringReference
import org.jf.dexlib2.immutable.ImmutableClassDef
import org.jf.dexlib2.immutable.ImmutableDexFile
import org.jf.dexlib2.immutable.ImmutableMethod
import org.jf.dexlib2.immutable.ImmutableMethodParameter
import org.jf.dexlib2.immutable.reference.ImmutableMethodReference
import org.jf.dexlib2.immutable.reference.ImmutableStringReference
import org.jf.dexlib2.immutable.reference.ImmutableTypeReference
import org.jf.dexlib2.rewriter.DexRewriter
import org.jf.dexlib2.rewriter.Rewriter
import org.jf.dexlib2.rewriter.RewriterModule
import org.jf.dexlib2.rewriter.Rewriters
import java.io.File
import java.security.SecureRandom

/** StringFog 配置 */
class FogOptions(
    /** 加密开关 */
    val enabled: Boolean = true,
    /** 每个字符串的随机密钥长度，原版默认 8 */
    val keyLength: Int = 8,
    /** 增强模式：多趟变形 + 干扰指令 */
    val enhanced: Boolean = false,
    /** 垃圾倍率：每个字符串垫多少条废弃指令，1..100 */
    val junkCount: Int = 5
) {
    fun isEmpty() = !enabled
}

/**
 * StringFog 的 DEX 层实现，bytes 存放模式。
 *
 * 普通版：单趟重复密钥 XOR（完全对齐原版 StringFogImpl）。
 *
 * 增强版：把明文过一条 4 趟流水线，运行时反序回推：
 *
 *   正向（加密）                     反向（解密）
 *   1) b ^= key[(i+1) % kl]          4) nibbleSwap(b)
 *   2) b  = (b + 0x5A) & 0xFF        3) b ^= key[(i+2) % kl]
 *   3) b ^= key[(i+2) % kl]          2) b  = (b - 0x5A) & 0xFF
 *   4) b  = nibbleSwap(b)            1) b ^= key[(i+1) % kl]
 *
 * 辘换位是自逆的，异或也是自逆的，所以反序回推就是正逆。
 * 密钥按 `(i + 趟号) % 密钥长` 轮转，不需要多存一份密钥。
 *
 * 调用点现场看：
 *
 *   原： const-string  vX, "明文"
 *   改： const/16          vX, <长度>          （增强版还会先垫两条废弃常量）
 *        new-array        vX, vX, [B
 *        fill-array-data  vX, :payload
 *        invoke-static    {vX}, StringFog.decrypt([B)String
 *        move-result-object vX
 *
 * 关键：长度 / 数组 / 源全部复用原本装那个字符串的 vX，**一个额外寄存器都不用**。
 */
/** 只用来造占位 label；这些 label 从不会被写进产物 */
private val SCRATCH_MMI = MutableMethodImplementation(1)
private fun placeholderLabel(): Label = SCRATCH_MMI.newLabelForIndex(0)

object StringFogObfuscator {

    private const val HELPER_TYPE = "Lcom/secure/StringFog;"
    private const val HELPER_NAME = "decrypt"
    private const val MAX_ARRAY = 32000
    private const val ADD_CONST = 0x5A

    fun apply(
        dexFiles: List<Pair<String, ByteArray>>,
        cacheDir: File,
        options: FogOptions
    ): List<Pair<String, ByteArray>> {
        if (dexFiles.isEmpty() || options.isEmpty()) return dexFiles
        replacedCount = 0
        lastError = null
        junkCount = options.junkCount.coerceIn(1, 100)
        val opcodes = Opcodes.getDefault()

        val loaded = ArrayList<Pair<String, DexFile>>(dexFiles.size)
        for ((i, entry) in dexFiles.withIndex()) {
            val tmp = File(cacheDir, "fog_src_$i.dex")
            try {
                tmp.writeBytes(entry.second)
                loaded.add(entry.first to DexFileFactory.loadDexFile(tmp, opcodes))
            } finally {
                tmp.delete()
            }
        }

        for ((_, dex) in loaded) {
            for (c in dex.classes) if (c.type == HELPER_TYPE) return dexFiles
        }

        val random = SecureRandom()
        val keyLength = options.keyLength.coerceIn(1, 32)
        val enhanced = options.enhanced

        val rewriter = DexRewriter(object : RewriterModule() {
            override fun getClassDefRewriter(rewriters: Rewriters): Rewriter<ClassDef> {
                val base = super.getClassDefRewriter(rewriters)
                return Rewriter { classDef ->
                    rebuild(base.rewrite(classDef), keyLength, random, enhanced)
                }
            }
        })

        val helper = buildHelperClass(enhanced) ?: return dexFiles

        val result = ArrayList<Pair<String, ByteArray>>(loaded.size)
        for ((i, entry) in loaded.withIndex()) {
            val rewritten = rewriter.getDexFileRewriter().rewrite(entry.second)
            val classes = rewritten.classes.toMutableList()
            if (i == 0) classes.add(helper)
            val tmp = File(cacheDir, "fog_dst_$i.dex")
            try {
                DexFileFactory.writeDexFile(tmp.absolutePath, ImmutableDexFile(opcodes, classes))
                result.add(entry.first to tmp.readBytes())
            } finally {
                tmp.delete()
            }
        }
        // 一个字符串都没换掉 -> 肯定是静默失败了，直接报出来，别再装作成功
        if (replacedCount == 0) {
            throw IllegalStateException("StringFog 没有替换任何字符串：${lastError ?: "未捕获异常"}")
        }
        return result
    }

    /** 诊断用：本次替换了多少个字符串、最后一条错误 */
    private var replacedCount = 0
    private var lastError: String? = null

    private fun rebuild(
        classDef: ClassDef,
        keyLength: Int,
        random: SecureRandom,
        enhanced: Boolean
    ): ClassDef {
        return ImmutableClassDef(
            classDef.type,
            classDef.accessFlags,
            classDef.superclass,
            classDef.interfaces.toList(),
            classDef.sourceFile,
            classDef.annotations,
            classDef.staticFields.toList(),
            classDef.instanceFields.toList(),
            classDef.directMethods.map { rewriteMethod(it, keyLength, random, enhanced) },
            classDef.virtualMethods.map { rewriteMethod(it, keyLength, random, enhanced) }
        )
    }

    /**
     * 把方法里所有 const-string 换成「byte[] + 解密调用」。
     * 倒着改 + 跳转目标自己重指 + payload 最后追加，思路和上一版一致。
     */
    private fun rewriteMethod(
        method: Method,
        keyLength: Int,
        random: SecureRandom,
        enhanced: Boolean
    ): Method {
        val impl = method.implementation ?: return method
        try {
            val mmi = MutableMethodImplementation(impl)
            val list = mmi.instructions.toList()

            for (ins in list) {
                val op = ins.opcode
                if (op == Opcode.PACKED_SWITCH || op == Opcode.SPARSE_SWITCH ||
                    op == Opcode.FILL_ARRAY_DATA
                ) return method
            }

            val fogAt = BooleanArray(list.size)
            var anyFog = false
            for (k in list.indices) {
                val raw = list[k]
                if (raw is OneRegisterInstruction && raw is ReferenceInstruction &&
                    raw.reference is StringReference
                ) {
                    fogAt[k] = true
                    anyFog = true
                }
            }
            if (!anyFog) return method

            val branchAt = HashMap<Int, Int>()
            for (k in list.indices) {
                val raw = list[k]
                if (raw is BuilderOffsetInstruction) branchAt[k] = raw.target.getLocation().getIndex()
            }

            val decryptRef = ImmutableMethodReference(
                HELPER_TYPE, HELPER_NAME, listOf("[B"), "Ljava/lang/String;"
            )
            val placeholder = placeholderLabel()

            class Site(val oldIndex: Int, val reg: Int, val bytes: ByteArray)
            val sites = ArrayList<Site>()

            for (k in list.indices.reversed()) {
                if (!fogAt[k]) continue
                val raw = list[k]
                if (raw !is OneRegisterInstruction || raw !is ReferenceInstruction) continue
                val reg = raw.registerA
                val packed = pack((raw.reference as StringReference).string, keyLength, random, enhanced)
                if (packed.size > MAX_ARRAY) continue

                var cursor = k
                if (enhanced) {
                    // 花里胡哨：按「垃圾倍率」垫一堆废弃指令（常量 + 算术交替），
                    // 运行时全用不到，马上就会被真实长度覆盖。
                    mmi.replaceInstruction(cursor, deadIns(reg, k, 0))
                    for (n in 1 until junkCount) {
                        mmi.addInstruction(++cursor, deadIns(reg, k, n))
                    }
                }
                val lenIns = if (packed.size <= 7)
                    BuilderInstruction11n(Opcode.CONST_4, reg, packed.size)
                else
                    BuilderInstruction21s(Opcode.CONST_16, reg, packed.size)
                if (enhanced) mmi.addInstruction(++cursor, lenIns)
                else mmi.replaceInstruction(cursor, lenIns)

                mmi.addInstruction(++cursor, BuilderInstruction22c(Opcode.NEW_ARRAY, reg, reg, ImmutableTypeReference("[B")))
                mmi.addInstruction(++cursor, BuilderInstruction31t(Opcode.FILL_ARRAY_DATA, reg, placeholder))
                mmi.addInstruction(++cursor, BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, reg, 0, 0, 0, 0, decryptRef))
                mmi.addInstruction(++cursor, BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, reg))
                sites.add(Site(k, reg, packed))
            }
            replacedCount += sites.size

            // 每个站点净增指令数：普通 4，增强 6
            // 每个站点净增指令：普通 4；增强 = 垃圾条数 + 4
            // （junkCount 条垃圾里第一条是替换、其余 junkCount-1 条是新增，再加长度 1 条 + 后四条）
            val grow = if (enhanced) junkCount + 4 else 4
            val offset = IntArray(list.size + 1)
            for (k in list.indices) offset[k + 1] = offset[k] + if (fogAt[k]) grow else 0
            fun newIndex(old: Int): Int = old + offset[old.coerceIn(0, list.size)]

            for ((oldIdx, oldTarget) in branchAt) {
                val at = newIndex(oldIdx)
                val current = mmi.instructions[at]
                if (current !is BuilderOffsetInstruction) continue
                val label = mmi.newLabelForIndex(newIndex(oldTarget))
                mmi.replaceInstruction(at, rebuildBranch(current, label))
            }

            for (site in sites) {
                val payload = BuilderArrayPayload(1, site.bytes.toList())
                mmi.addInstruction(payload)
                val payloadLabel = mmi.newLabelForIndex(mmi.instructions.size - 1)
                // 每个站点里 fill-array-data 的相对位置：普通 +2、增强 +4
                mmi.replaceInstruction(
                    newIndex(site.oldIndex) + (if (enhanced) junkCount + 2 else 2),
                    BuilderInstruction31t(Opcode.FILL_ARRAY_DATA, site.reg, payloadLabel)
                )
            }

            return ImmutableMethod(
                method.definingClass, method.name, method.parameters.toList(), method.returnType,
                method.accessFlags, method.annotations, method.hiddenApiRestrictions, mmi
            )
        } catch (e: Exception) {
            if (lastError == null) lastError = e.message ?: e.toString()
            return method
        }
    }

    /**
     * 干扰用的废弃常量。
     * 必须掩到 16 位有符号范围（-32768..32767）：const/16 装不下的话
     * dexlib2 构造指令时会抛异常，被 catch 吞掉后整个方法静默还原、字符串一个不换。
     */
    private fun deadConst(seed: Int): Int = (0x1A2B xor (seed * 0x9E37)) and 0x7FFF

    /** 22b 的立即数是 8 位有符号，压到 0..127 */
    private fun deadLit(seed: Int): Int = (0x2B + seed * 0x37) and 0x7F

    /** 造一条废弃指令：只写 reg，随后就会被真实长度覆盖 */
    private fun deadIns(reg: Int, seed: Int, n: Int): BuilderInstruction = when (n % 3) {
        0 -> BuilderInstruction21s(Opcode.CONST_16, reg, deadConst(seed * 31 + n))
        1 -> BuilderInstruction22b(Opcode.ADD_INT_LIT8, reg, reg, deadLit(seed + n))
        else -> BuilderInstruction22b(Opcode.AND_INT_LIT8, reg, reg, deadLit(seed * 7 + n))
    }

    /** 垃圾倍率，apply() 开头的 options.junkCount 赋值 */
    private var junkCount = 5

    private fun rebuildBranch(ins: BuilderOffsetInstruction, label: Label): BuilderInstruction {
        return when (ins) {
            is BuilderInstruction10t -> BuilderInstruction10t(ins.opcode, label)
            is BuilderInstruction20t -> BuilderInstruction20t(ins.opcode, label)
            is BuilderInstruction30t -> BuilderInstruction30t(ins.opcode, label)
            is BuilderInstruction21t -> BuilderInstruction21t(ins.opcode, ins.registerA, label)
            is BuilderInstruction22t -> BuilderInstruction22t(ins.opcode, ins.registerA, ins.registerB, label)
            else -> ins
        }
    }

    /**
     * 打包成 [密钥长度][密钥][密文]。
     * 密钥是**每个字符串各自随机的**（对齐原版 RandomKeyGenerator）。
     */
    private fun pack(
        plain: String,
        keyLength: Int,
        random: SecureRandom,
        enhanced: Boolean
    ): ByteArray {
        val data = plain.toByteArray(Charsets.UTF_8)
        val key = ByteArray(keyLength)
        random.nextBytes(key)
        val kl = key.size

        if (!enhanced) {
            var j = 0
            for (i in data.indices) {
                if (j >= kl) j = 0
                data[i] = (data[i].toInt() xor key[j].toInt()).toByte()
                j++
            }
        } else {
            for (i in data.indices) data[i] = (data[i].toInt() xor key[(i + 1) % kl].toInt()).toByte()
            for (i in data.indices) data[i] = ((data[i].toInt() + ADD_CONST) and 0xFF).toByte()
            for (i in data.indices) data[i] = (data[i].toInt() xor key[(i + 2) % kl].toInt()).toByte()
            for (i in data.indices) {
                val b = data[i].toInt() and 0xFF
                data[i] = (((b and 0x0F) shl 4) or (b shr 4)).toByte()
            }
        }

        val out = ByteArray(1 + kl + data.size)
        out[0] = kl.toByte()
        System.arraycopy(key, 0, out, 1, kl)
        System.arraycopy(data, 0, out, 1 + kl, data.size)
        return out
    }

    // ==================== 汇编辅助 ====================

    /**
     * 字节码组装器。
     * 所有跳转目标靠名字标记，最后统一回填 —— 不用手写任何下标，
     * 避开了之前「数错下标 -> 方法结构错乱 -> 闪退」那类问题。
     */
    private class Asm(private val registerCount: Int) {

        private class Pending(
            val at: Int,
            val target: String,
            val opcode: Opcode,
            val a: Int,
            val b: Int,
            val isGoto: Boolean
        )

        private val pool = ArrayList<BuilderInstruction>()
        private val labels = HashMap<String, Int>()
        private val pending = ArrayList<Pending>()

        fun mark(name: String) {
            labels[name] = pool.size
        }

        fun add(ins: BuilderInstruction) {
            pool.add(ins)
        }

        fun goto(target: String) {
            pending.add(Pending(pool.size, target, Opcode.GOTO_32, 0, 0, true))
            pool.add(BuilderInstruction30t(Opcode.GOTO_32, placeholderLabel()))
        }

        fun branch(op: Opcode, a: Int, b: Int, target: String) {
            pending.add(Pending(pool.size, target, op, a, b, false))
            pool.add(BuilderInstruction22t(op, a, b, placeholderLabel()))
        }

        fun build(): MutableMethodImplementation? {
            val m = MutableMethodImplementation(registerCount)
            for (x in pool) m.addInstruction(x)
            for (p in pending) {
                val idx = labels[p.target] ?: return null
                val label = m.newLabelForIndex(idx)
                val ins = if (p.isGoto) BuilderInstruction30t(Opcode.GOTO_32, label)
                else BuilderInstruction22t(p.opcode, p.a, p.b, label)
                m.replaceInstruction(p.at, ins)
            }
            return m
        }
    }

    // ==================== 运行时 helper ====================

    private fun buildHelperClass(enhanced: Boolean): ClassDef? {
        val ct = HELPER_TYPE
        // helper 建不出来（label 对不上）就整个放弃混淆
        val m = (if (enhanced) buildEnhanced() else buildPlain()) ?: return null

        return ImmutableClassDef(
            ct,
            AccessFlags.PUBLIC.value or AccessFlags.FINAL.value,
            "Ljava/lang/Object;",
            emptyList(), null, ImmutableSet.of(), emptyList(), emptyList(),
            listOf(
                ImmutableMethod(
                    ct, HELPER_NAME,
                    listOf(ImmutableMethodParameter("[B", ImmutableSet.of(), null)),
                    "Ljava/lang/String;",
                    AccessFlags.PUBLIC.value or AccessFlags.STATIC.value,
                    ImmutableSet.of(), ImmutableSet.of(), m
                )
            ), emptyList()
        )
    }

    /**
     * 普通版：单趟重复密钥 XOR。
     *   public static String decrypt(byte[] p) {
     *       int klen = p[0];
     *       int n = p.length;
     *       int j = 0;
     *       for (int i = klen + 1; i < n; i++) {
     *           if (j >= klen) j = 0;
     *           p[i] = (byte)(p[i] ^ p[1 + j]);
     *           j++;
     *       }
     *       return new String(p, klen + 1, n - klen - 1, "UTF-8");
     *   }
     */
    private fun buildPlain(): MutableMethodImplementation? {
        val a = Asm(10)
        // v0=klen v1=n v2=i v3=j v4/v5=临时 v6=offset v7=length v8="UTF-8" v9=p
        a.add(BuilderInstruction11n(Opcode.CONST_4, 3, 0))
        a.add(BuilderInstruction23x(Opcode.AGET_BYTE, 0, 9, 3))
        a.add(BuilderInstruction12x(Opcode.ARRAY_LENGTH, 1, 9))
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 2, 0, 1))
        a.mark("loop")
        a.branch(Opcode.IF_GE, 2, 1, "end")
        a.branch(Opcode.IF_LT, 3, 0, "xor")
        a.add(BuilderInstruction11n(Opcode.CONST_4, 3, 0))
        a.mark("xor")
        a.add(BuilderInstruction23x(Opcode.AGET_BYTE, 4, 9, 2))
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 5, 3, 1))
        a.add(BuilderInstruction23x(Opcode.AGET_BYTE, 5, 9, 5))
        a.add(BuilderInstruction23x(Opcode.XOR_INT, 4, 4, 5))
        a.add(BuilderInstruction12x(Opcode.INT_TO_BYTE, 4, 4))
        a.add(BuilderInstruction23x(Opcode.APUT_BYTE, 4, 9, 2))
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 2, 2, 1))
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 3, 3, 1))
        a.goto("loop")
        a.mark("end")
        addReturn(a)
        return a.build()
    }

    /**
     * 增强版：4 趟反序回推，四个循环，全是跳转，很难一眼看出在干什么。
     *
     *   int klen = p[0];
     *   int n = p.length;
     *   for (i = klen+1; i < n; i++) p[i] = nibbleSwap(p[i]);
     *   for (i = klen+1; i < n; i++) p[i] ^= p[1 + (i+2) % klen];
     *   for (i = klen+1; i < n; i++) p[i] -= 0x5A;
     *   for (i = klen+1; i < n; i++) p[i] ^= p[1 + (i+1) % klen];
     *   return new String(p, klen+1, n-klen-1, "UTF-8");
     */
    private fun buildEnhanced(): MutableMethodImplementation? {
        val a = Asm(10)
        a.add(BuilderInstruction11n(Opcode.CONST_4, 3, 0))
        a.add(BuilderInstruction23x(Opcode.AGET_BYTE, 0, 9, 3))
        a.add(BuilderInstruction12x(Opcode.ARRAY_LENGTH, 1, 9))

        // 第一趟：高低四位互换
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 2, 0, 1))
        a.mark("l1")
        a.branch(Opcode.IF_GE, 2, 1, "l2")
        a.add(BuilderInstruction23x(Opcode.AGET_BYTE, 4, 9, 2))
        a.add(BuilderInstruction22b(Opcode.AND_INT_LIT8, 5, 4, 0x0F))
        a.add(BuilderInstruction22b(Opcode.SHL_INT_LIT8, 5, 5, 4))
        a.add(BuilderInstruction22b(Opcode.SHR_INT_LIT8, 4, 4, 4))
        a.add(BuilderInstruction22b(Opcode.AND_INT_LIT8, 4, 4, 0x0F))
        a.add(BuilderInstruction23x(Opcode.OR_INT, 5, 5, 4))
        a.add(BuilderInstruction12x(Opcode.INT_TO_BYTE, 5, 5))
        a.add(BuilderInstruction23x(Opcode.APUT_BYTE, 5, 9, 2))
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 2, 2, 1))
        a.goto("l1")

        // 第二趟：异或 key[(i+2) % klen]
        a.mark("l2")
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 2, 0, 1))
        a.mark("l2loop")
        a.branch(Opcode.IF_GE, 2, 1, "l3")
        // 密钥下标必须用「数据内下标」。i 是打包数组下标，数据从 klen+1 开始，
        // 所以 i - klen 恰好等于「数据下标 + 1」。
        // 本趟要用的密钥是 key[(数据下标 + 2) % klen]。
        // i = klen + 1 + d，所以 (i + 1) % klen 正好等于 (d + 2) % klen。
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 5, 2, 1))
        a.add(BuilderInstruction23x(Opcode.REM_INT, 5, 5, 0))
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 5, 5, 1))
        a.add(BuilderInstruction23x(Opcode.AGET_BYTE, 4, 9, 2))
        a.add(BuilderInstruction23x(Opcode.AGET_BYTE, 6, 9, 5))
        a.add(BuilderInstruction23x(Opcode.XOR_INT, 4, 4, 6))
        a.add(BuilderInstruction12x(Opcode.INT_TO_BYTE, 4, 4))
        a.add(BuilderInstruction23x(Opcode.APUT_BYTE, 4, 9, 2))
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 2, 2, 1))
        a.goto("l2loop")

        // 第三趟：减常量
        a.mark("l3")
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 2, 0, 1))
        a.mark("l3loop")
        a.branch(Opcode.IF_GE, 2, 1, "l4")
        a.add(BuilderInstruction23x(Opcode.AGET_BYTE, 4, 9, 2))
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 4, 4, -ADD_CONST))
        a.add(BuilderInstruction12x(Opcode.INT_TO_BYTE, 4, 4))
        a.add(BuilderInstruction23x(Opcode.APUT_BYTE, 4, 9, 2))
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 2, 2, 1))
        a.goto("l3loop")

        // 第四趟：异或 key[(i+1) % klen]
        a.mark("l4")
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 2, 0, 1))
        a.mark("l4loop")
        a.branch(Opcode.IF_GE, 2, 1, "end")
        // 本趟要用的密钥是 key[(数据下标 + 1) % klen]。
        // i - klen = d + 1，直接就是它，不能再加 1。
        a.add(BuilderInstruction23x(Opcode.SUB_INT, 5, 2, 0))
        a.add(BuilderInstruction23x(Opcode.REM_INT, 5, 5, 0))
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 5, 5, 1))
        a.add(BuilderInstruction23x(Opcode.AGET_BYTE, 4, 9, 2))
        a.add(BuilderInstruction23x(Opcode.AGET_BYTE, 6, 9, 5))
        a.add(BuilderInstruction23x(Opcode.XOR_INT, 4, 4, 6))
        a.add(BuilderInstruction12x(Opcode.INT_TO_BYTE, 4, 4))
        a.add(BuilderInstruction23x(Opcode.APUT_BYTE, 4, 9, 2))
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 2, 2, 1))
        a.goto("l4loop")

        a.mark("end")
        addReturn(a)
        return a.build()
    }

    /** return new String(p, klen + 1, n - klen - 1, "UTF-8"); */
    private fun addReturn(a: Asm) {
        a.add(BuilderInstruction21c(Opcode.CONST_STRING, 8, ImmutableStringReference("UTF-8")))
        a.add(BuilderInstruction21c(Opcode.NEW_INSTANCE, 5, ImmutableTypeReference("Ljava/lang/String;")))
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 6, 0, 1))
        a.add(BuilderInstruction23x(Opcode.SUB_INT, 7, 1, 0))
        a.add(BuilderInstruction22b(Opcode.ADD_INT_LIT8, 7, 7, -1))
        a.add(
            BuilderInstruction35c(
                Opcode.INVOKE_DIRECT, 5, 5, 9, 6, 7, 8,
                ImmutableMethodReference(
                    "Ljava/lang/String;", "<init>",
                    listOf("[B", "I", "I", "Ljava/lang/String;"), "V"
                )
            )
        )
        a.add(BuilderInstruction11x(Opcode.RETURN_OBJECT, 5))
    }
}
