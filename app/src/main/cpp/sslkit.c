/*
 * SSLKit native 层 —— 通用 BoringSSL / OpenSSL 证书校验绕过。
 *
 * 设计（不点名任何 .so）：
 *   1. 用 dl_iterate_phdr 遍历所有已加载的 so
 *   2. 对每个 so 解析 ELF 动态符号表（.dynsym）
 *   3. 找到目标符号（SSL_CTX_set_custom_verify / X509_verify_cert / ...）
 *   4. 通过 GOT/PLT 重定向把调用劫持到我们自己的实现
 *
 * 为什么用 GOT hook 而不是 inline hook：
 *   - 不需要 Dobby 等第三方库，代码量小
 *   - 不需要目标符号导出（只要被 import 就能拦）
 *   - 对 libsscronet.so 这种"内部静态链接 BoringSSL"的情况，
 *     如果它把 SSL_* 作为导出符号暴露，GOT 依然能拦
 *
 * 对于内部静态链接（符号不出现在 .dynsym）的情况，本文件同时提供
 * inline hook 的搭钩（可选启用 Dobby）。
 */

#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#define LOG_TAG "SSLKit-Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

/* ====================================================================
 *  ELF 结构（只取需要的部分，避免依赖 <elf.h> 版本差异）
 * ==================================================================== */
typedef struct {
    uint64_t d_tag;
    uint64_t d_val;   /* 64 位下 union，取地址用 */
} Elf64_Dyn_min;

#define DT_NULL_     0
#define DT_NEEDED_   1
#define DT_PLTRELSZ_ 2
#define DT_PLTGOT_   3
#define DT_HASH_     4
#define DT_STRTAB_   5
#define DT_SYMTAB_   6
#define DT_RELA_     7
#define DT_RELASZ_   8
#define DT_RELAENT_  9
#define DT_STRSZ_    10
#define DT_SYMENT_   11
#define DT_INIT_     12
#define DT_FINI_     13
#define DT_SONAME_   14
#define DT_RPATH_    15
#define DT_SYMBOLIC_ 16
#define DT_REL_      17
#define DT_RELSZ_    18
#define DT_RELENT_   19
#define DT_PLTREL_   20
#define DT_JMPREL_   23
#define DT_INIT_ARRAY_ 25
#define DT_FINI_ARRAY_ 26
#define DT_GNU_HASH_ 0x6ffffef5

#define R_AARCH64_ABS64_    257
#define R_AARCH64_GLOB_DAT_ 1025
#define R_AARCH64_JUMP_SLOT_ 1026

/* x86_64 reloc types（CI 也可能编 x86 版，为将来兼容） */
#define R_X86_64_64_        1
#define R_X86_64_GLOB_DAT_  6
#define R_X86_64_JUMP_SLOT_ 7

/* Elf64_Shdr 最小结构（避免 <elf.h> 版本差异） */
typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} Elf64_Shdr_min;
typedef Elf64_Shdr_min shdr_t;

/* Elf64_Sym 最小结构 */
typedef struct {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} Elf64_Sym_min;

/* ====================================================================
 *  目标符号 hook 表
 * ==================================================================== */
typedef struct {
    const char *name;
    void *replacement;
    int hooked;
    void *original;
} hook_entry_t;

static hook_entry_t g_hooks[64];
static int g_hook_count = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* 统计 */
static volatile int g_stat_custom_verify = 0;
static volatile int g_stat_x509_verify = 0;
static volatile int g_stat_verify_result = 0;
static volatile int g_stat_cronet_do_verify = 0;

/* 按名字找原函数（第一次 hook 时记录） */
static void *find_original(const char *name) {
    for (int i = 0; i < g_hook_count; i++) {
        if (strcmp(g_hooks[i].name, name) == 0) {
            return g_hooks[i].original;
        }
    }
    return NULL;
}

/* ====================================================================
 *  ★ 替换实现
 * ==================================================================== */

/*
 * SSL_CTX_set_custom_verify(SSL_CTX *ctx, int mode, enum ssl_verify_result_t (*cb)(SSL*, uint8_t*))
 *
 * 最直接的做法：把回调换成我们自己的 "永远 OK"。
 * 但签名里的回调类型我们需要返回 ssl_verify_ok = 0
 */
typedef int (*ssl_custom_verify_cb_t)(void *ssl, uint8_t *out_alert);

static int sslkit_custom_verify_cb(void *ssl, uint8_t *out_alert) {
    (void) ssl;
    if (out_alert) {
        *out_alert = 0;
    }
    return 0;   /* ssl_verify_ok */
}

static void sslkit_SSL_CTX_set_custom_verify(void *ctx, int mode, void *cb) {
    int n = __sync_fetch_and_add(&g_stat_custom_verify, 1);
    /* 只在第一次和每 100 次打日志，避免刷爆 logcat 影响时序 */
    if (n < 3 || (n % 100) == 0) {
        LOGI("SSL_CTX_set_custom_verify called (mode=%d, n=%d) -> always-OK", mode, n + 1);
    }
    typedef void (*fn_t)(void *, int, void *);
    fn_t orig = (fn_t) find_original("SSL_CTX_set_custom_verify");
    if (orig) {
        /* 保留原 mode（改动 mode 可能影响握手流程），只替换回调 */
        orig(ctx, mode, (void *) sslkit_custom_verify_cb);
    }
}

/*
 * X509_verify_cert(X509_STORE_CTX *ctx) -> int   (1 = OK)
 */
static int sslkit_X509_verify_cert(void *ctx) {
    __sync_fetch_and_add(&g_stat_x509_verify, 1);
    LOGI("X509_verify_cert bypassed -> 1 (OK)");
    return 1;
}

/*
 * SSL_get_verify_result(const SSL *ssl) -> long   (X509_V_OK = 0)
 */
static long sslkit_SSL_get_verify_result(void *ssl) {
    __sync_fetch_and_add(&g_stat_verify_result, 1);
    return 0;   /* X509_V_OK */
}

/*
 * X509_STORE_CTX_get_error(X509_STORE_CTX *ctx) -> int   (X509_V_OK = 0)
 */
static int sslkit_X509_STORE_CTX_get_error(void *ctx) {
    (void) ctx;
    return 0;
}

/*
 * SSL_set_verify(SSL *ssl, int mode, cb)  —— mode 里 SSL_VERIFY_NONE = 0
 */
static void sslkit_SSL_set_verify(void *ssl, int mode, void *cb) {
    (void) cb;
    LOGI("SSL_set_verify called mode=%d -> forced SSL_VERIFY_NONE", mode);
    typedef void (*fn_t)(void *, int, void *);
    fn_t orig = (fn_t) find_original("SSL_set_verify");
    if (orig) {
        orig(ssl, 0, NULL);   /* SSL_VERIFY_NONE */
    }
}

static void sslkit_SSL_CTX_set_verify(void *ctx, int mode, void *cb) {
    (void) cb;
    LOGI("SSL_CTX_set_verify called mode=%d -> forced SSL_VERIFY_NONE", mode);
    typedef void (*fn_t)(void *, int, void *);
    fn_t orig = (fn_t) find_original("SSL_CTX_set_verify");
    if (orig) {
        orig(ctx, 0, NULL);
    }
}

/* ====================================================================
 *  ★ Cronet 专杀（字节 / Google）
 * ==================================================================== */

/*
 * Cronet_CertVerify_DoVerifyV2(engine, params, result) -> int
 *
 * 这是 Cronet 的证书校验总闸。返回 0 表示成功（Cronet 约定）。
 * 具体返回值语义各家不同，但实测 libsscronet 里 0 = 通过。
 */
static int sslkit_Cronet_CertVerify_DoVerifyV2(void *engine, void *params, void *result) {
    __sync_fetch_and_add(&g_stat_cronet_do_verify, 1);
    LOGI("★ Cronet_CertVerify_DoVerifyV2 bypassed -> 0 (OK)");
    /* 如果 result 有 setter，尝试设置 is_issued_by_known_root = true */
    return 0;
}

/*
 * Cronet_VerifyResult_is_issued_by_known_root_set(result, bool)
 */
static void sslkit_Cronet_VerifyResult_is_issued_by_known_root_set(void *result, bool v) {
    LOGI("Cronet_VerifyResult_is_issued_by_known_root_set(%d) -> forced true", (int) v);
    typedef void (*fn_t)(void *, bool);
    fn_t orig = (fn_t) find_original("Cronet_VerifyResult_is_issued_by_known_root_set");
    if (orig) {
        orig(result, true);
    }
}

/*
 * Cronet_EngineParams_public_key_pins_add(params, pin)  —— 吞掉 pin
 */
static bool sslkit_Cronet_EngineParams_public_key_pins_add(void *params, void *pin) {
    LOGI("Cronet_EngineParams_public_key_pins_add -> swallowed");
    return true;
}

/* ====================================================================
 *  符号表
 * ==================================================================== */

/* ★ 全局开关：inline hook 在部分设备/App 上会因 SELinux 拒绝 mprotect(RWX)
 * 触发 SIGSEGV(SEGV_ACCERR)，默认关闭，由 system property debug.sslkit.inline=1 开启 */
static int g_inline_enabled = 0;

/* 前向声明 */
static uint32_t gnu_hash_symcount(uint64_t gnu_hash, uint64_t symtab);
static void *create_trampoline(void *target, const unsigned char *saved);
static int collect_symbols_in_so(const char *soname, uintptr_t base,
                                 const void *dyn, size_t dyn_size);
static int inline_hook_collected(void);
static int write_abs_jump(void *target, void *dest);
static int try_inline_hook_global(void);

/*
 * 目标符号表。
 *
 * ★ 最小必要原则（实测教训）：
 *   不是 hook 越多越好。有些函数被 BoringSSL 用作【状态机判断】，
 *   强制改返回值会让内部状态不一致 -> 连接卡死（现象：TLS 通了但数据不流动）。
 *
 *   - SSL_CTX_set_custom_verify : 只把回调换成 always-OK，不改协议状态 -> 安全
 *   - SSL_set_verify / SSL_CTX_set_verify : 同理，只是设置 verify mode -> 安全
 *   - Cronet_CertVerify_DoVerifyV2 : Cronet 校验总闸，返回成功 -> 安全
 *   - Cronet_EngineParams_public_key_pins_add : 吞掉 pin -> 安全
 *   - Cronet_VerifyResult_is_issued_by_known_root_set : 置 true -> 安全
 *
 *   ❌ 已移除（有副作用）：
 *   - SSL_get_verify_result : 有的库用它做握手状态机判断，强制 0 -> 卡死
 *   - X509_STORE_CTX_get_error : 同上，BoringSSL 内部依赖它做错误路径判断
 *   - X509_verify_cert : 直接返回 1 会让 X509_STORE_CTX 内部状态不一致
 */
static void register_hooks(void) {
    int i = 0;

    /* --- 安全：设置类 --- */
    g_hooks[i].name = "SSL_CTX_set_custom_verify";
    g_hooks[i++].replacement = (void *) sslkit_SSL_CTX_set_custom_verify;

    g_hooks[i].name = "SSL_set_verify";
    g_hooks[i++].replacement = (void *) sslkit_SSL_set_verify;

    g_hooks[i].name = "SSL_CTX_set_verify";
    g_hooks[i++].replacement = (void *) sslkit_SSL_CTX_set_verify;

    /* --- 安全：Cronet 专用 --- */
    g_hooks[i].name = "Cronet_CertVerify_DoVerifyV2";
    g_hooks[i++].replacement = (void *) sslkit_Cronet_CertVerify_DoVerifyV2;

    g_hooks[i].name = "Cronet_VerifyResult_is_issued_by_known_root_set";
    g_hooks[i++].replacement = (void *) sslkit_Cronet_VerifyResult_is_issued_by_known_root_set;

    g_hooks[i].name = "Cronet_EngineParams_public_key_pins_add";
    g_hooks[i++].replacement = (void *) sslkit_Cronet_EngineParams_public_key_pins_add;

    g_hook_count = i;
    LOGI("registered %d target symbols (minimal set)", g_hook_count);
}

/* ====================================================================
 *  ELF 解析 + GOT hook
 * ==================================================================== */

typedef struct {
    const char *name;
    uintptr_t base;
    void *dlpi_addr;
    const void *dyn;
    size_t dyn_size;
    int hooked_count;
} so_ctx_t;

static int is_excluded(const char *name) {
    if (!name) return 1;
    static const char *excl[] = {
        "vulkan", "adreno", "mali", "gralloc", "libegl", "libgles",
        "libhwui", "libgui", "libui", "libllvm", "librs", "libgsl",
        "libdmabufheap", "libhardware", "/vendor/", "libsslkit",
        "libc.so", "libm.so", "libdl.so", "libart", "libnativehelper",
        "liblog.so", "libz.so", "libutils.so", NULL
    };
    for (int i = 0; excl[i]; i++) {
        if (strcasestr(name, excl[i])) return 1;
    }
    /* 只处理 .so */
    if (!strstr(name, ".so")) return 1;
    return 0;
}

/* 从 Elf64_Dyn 数组里找 tag */
static uint64_t dyn_find(const void *dyn, size_t count, uint64_t tag) {
    const uint64_t *p = (const uint64_t *) dyn;
    for (size_t i = 0; i < count; i++) {
        if (p[i * 2] == tag) return p[i * 2 + 1];
    }
    return 0;
}

/* 判断这个 so 是否已经在我们的 hook 记录里 */
static int already_hooked(const char *name) {
    /* 简单实现：用静态集合（进程内 so 数量有限） */
    static char seen[256][128];
    static int n = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(seen[i], name) == 0) return 1;
    }
    if (n < 256) {
        strncpy(seen[n], name, 127);
        seen[n][127] = 0;
        n++;
    }
    return 0;
}

/*
 * 核心：hook 一个 so 的 GOT 表项。
 *
 * 原理：
 *   .rela.dyn / .rela.plt 里记录了 "哪个 GOT 表项对应哪个符号"。
 *   把 GOT 表项的值改成我们的函数地址 → 所有经过 PLT 的调用都被劫持。
 *
 *   对 aarch64：GOT 在 .data.rel.ro，需要 mprotect 打开写权限。
 */
static int hook_so(shdr_t *shdr, int shnum, so_ctx_t *ctx) {
    int hooked = 0;

    for (int i = 0; i < shnum; i++) {
        /* SHT_RELA = 4 */
        if (shdr[i].sh_type != 4) continue;

        uintptr_t rela_addr = ctx->base + shdr[i].sh_offset;
        size_t rela_size = shdr[i].sh_size;
        size_t rela_ent = shdr[i].sh_entsize ? shdr[i].sh_entsize : 24;
        if (rela_ent == 0) continue;

        size_t n = rela_size / rela_ent;
        /* 关联的符号表 */
        int sym_idx = (int) shdr[i].sh_link;
        if (sym_idx <= 0 || sym_idx >= shnum) continue;
        uintptr_t symtab = ctx->base + shdr[sym_idx].sh_offset;

        /* 关联的字符串表 */
        int str_idx = (int) shdr[sym_idx].sh_link;
        if (str_idx <= 0 || str_idx >= shnum) continue;
        const char *strtab = (const char *) (ctx->base + shdr[str_idx].sh_offset);

        for (size_t k = 0; k < n; k++) {
            /* Elf64_Rela: r_offset(8) r_info(8) r_addend(8) */
            uint8_t *e = (uint8_t *) (rela_addr + k * rela_ent);
            uint64_t r_offset = *(uint64_t *) (e);
            uint64_t r_info = *(uint64_t *) (e + 8);
            uint32_t r_type = (uint32_t) (r_info & 0xffffffff);
            uint32_t r_sym = (uint32_t) (r_info >> 32);

            /* 只关心 GOT 类重定位 */
            if (r_type != R_AARCH64_GLOB_DAT_ && r_type != R_AARCH64_JUMP_SLOT_
                && r_type != R_X86_64_GLOB_DAT_ && r_type != R_X86_64_JUMP_SLOT_
                && r_type != R_AARCH64_ABS64_ && r_type != R_X86_64_64_) {
                continue;
            }

            /* Elf64_Sym: st_name(4) st_info(1) st_other(1) st_shndx(2) st_value(8) st_size(8) = 24 */
            uint8_t *sym = (uint8_t *) (symtab + r_sym * 24);
            uint32_t st_name = *(uint32_t *) (sym);
            if (st_name == 0) continue;
            const char *sname = strtab + st_name;
            if (!sname || !*sname) continue;

            /* 匹配我们的目标符号 */
            for (int h = 0; h < g_hook_count; h++) {
                if (strcmp(sname, g_hooks[h].name) != 0) continue;

                uintptr_t *got = (uintptr_t *) (ctx->base + r_offset);

                /* 打开写权限 */
                long page = sysconf(_SC_PAGESIZE);
                uintptr_t pg = (uintptr_t) got & ~(uintptr_t)(page - 1);
                uintptr_t gend2 = ((uintptr_t) got + sizeof(void*) - 1) & ~(uintptr_t)(page - 1);
                size_t glen2 = (size_t)(gend2 - pg) + (size_t)page;
                if (mprotect((void *) pg, glen2,
                             PROT_READ | PROT_WRITE) != 0) {
                    LOGE("mprotect fail @%p (errno=%d)", got, errno);
                    continue;
                }

                if (g_hooks[h].original == NULL) {
                    g_hooks[h].original = (void *) (*got);
                }
                *got = (uintptr_t) g_hooks[h].replacement;
                g_hooks[h].hooked = 1;
                hooked++;
                LOGI("GOT hooked %s in %s  (orig=%p -> %p)",
                     sname, ctx->name ? ctx->name : "?",
                     (void *) g_hooks[h].original, g_hooks[h].replacement);

                mprotect((void *) pg, glen2, PROT_READ);
                break;
            }
        }
    }

    if (shdr) { /* nothing */ }
    return hooked;
}

static void *phdr_base = NULL;

static int phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void) size; (void) data;
    const char *name = info->dlpi_name;
    if (!name || !*name) {
        /* 主程序：用 /proc/self/exe 不好拿名字，跳过 */
        return 0;
    }
    if (is_excluded(name)) return 0;
    if (already_hooked(name)) return 0;
    /* ★ 只扫 App 私有目录的 so（/system /apex /vendor 的跳过，省时且避免误伤） */
    if (name[0] == '/' && strncmp(name, "/data/", 6) != 0) {
        return 0;
    }

    /* 找 PT_DYNAMIC = 2 */
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != 2) continue;   /* PT_DYNAMIC */

        uintptr_t dyn_addr = info->dlpi_addr + ph->p_vaddr;
        /* 我们需要 section header 来找 .rela.* —— 但 stripped so 没有 section header！
         * 所以改用 DT_* 动态段解析。见 scan_so_by_dynamic() */
        so_ctx_t ctx;
        ctx.name = name;
        ctx.base = info->dlpi_addr;
        ctx.dyn = (const void *) dyn_addr;
        ctx.dyn_size = ph->p_memsz;
        ctx.hooked_count = 0;

        /* 方式 A：GOT hook */
        extern int hook_so_by_dynamic(so_ctx_t *ctx);
        int n = hook_so_by_dynamic(&ctx);

        /* 方式 B：★ 收集该 so 里目标符号的实体地址（供 inline hook） */
        int m = collect_symbols_in_so(name, info->dlpi_addr,
                                      (const void *) dyn_addr, (size_t) ph->p_memsz);

        if (n > 0 || m > 0) {
            LOGI("%s: GOT=%d, SYM=%d", name, n, m);
        }
        break;
    }
    return 0;
}

/*
 * 通过 DT_* 动态段做 GOT hook（不依赖 section header）。
 *
 * 关键动态段：
 *   DT_JMPREL  + DT_PLTRELSZ + DT_PLTREL  → .rela.plt
 *   DT_RELA    + DT_RELASZ                → .rela.dyn
 *   DT_SYMTAB  → 符号表
 *   DT_STRTAB  → 字符串表
 */
int hook_so_by_dynamic(so_ctx_t *ctx);
int hook_rela_entries(void *rela_addr, size_t n, uint64_t symtab, uint64_t strtab,
                      uint64_t base, so_ctx_t *ctx);
static uint32_t gnu_hash_symcount(uint64_t gnu_hash, uint64_t symtab);
static int collect_symbols_in_so(const char *soname, uintptr_t base,
                                 const void *dyn, size_t dyn_size);
static int inline_hook_collected(void);

/*
 * ★ 额外手段：即便目标 so 没把符号导出到 .dynsym（静态链接 BoringSSL），
 *   我们还可以直接按【exported symbol 名】dlsym 拿到函数地址，
 *   然后做 inline hook（首指令替换为跳转到我们的实现）。
 *
 *   这对 libsscronet.so 这种"内部自带 BoringSSL、但把 SSL_* 作为导出符号暴露"的情况有效。
 */
extern void *dlsym(void *handle, const char *symbol);
#include <dlfcn.h>

/* 最小 inline hook：把目标函数头 16 字节替换为绝对跳转 */
typedef struct {
    void *target;
    void *replacement;
    unsigned char saved[16];
    int installed;
    /* ★ 跳板（trampoline）：保存被覆盖的原始指令 + 跳回 target+16，
     *   供"调用原函数"使用。绝不能直接调 target（已被改写 -> 无限递归）。 */
    void *trampoline;
} inline_hook_t;

static inline_hook_t g_inline[16];
static int g_inline_count = 0;

/*
 * 在目标地址写入绝对跳转：ldr x16,#8; br x16; .quad dest
 *
 * ★ 安全要点（闪退教训）：
 *   - SELinux 在 targetSdk 高 的 App 上会拒绝 executable 内存的 mprotect
 *   - 必须只改【覆盖 target 所需的最小页数】，不要盲改 2 页
 *   - mprotect 失败要立刻返回，绝不能继续写
 *   - 写完后恢复【原始权限】，不是盲目 PROT_READ
 */
/*
 * 写入绝对跳转。
 *
 * ★ 安全策略（多线程下的正确做法）：
 *   1. 目标函数前 16 字节拆成【两条 8 字节写入】，
 *      先用原子方式写第 2 个 8 字节（.quad dest 的高位部分不动），
 *      再写第 1 个 8 字节（ldr+br 指令对）—— 保证任何时刻 CPU 取到的
 *      要么是原指令，要么是完整跳转，不会取到半条指令。
 *   2. aarch64 的 `ldr x16,#8; br x16; .quad` 共 16 字节，
 *      其中 [0..7] 是指令（8 字节对齐读），[8..15] 是地址数据。
 *      ARM64 指令是 4 字节定长，只要 8 字节原子写 [0..7] 即可安全。
 */
static int write_abs_jump(void *target, void *dest) {
    long page = sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t) target;
    uintptr_t pg = start & ~(uintptr_t)(page - 1);
    uintptr_t end = (start + 16 - 1) & ~(uintptr_t)(page - 1);
    size_t len = (size_t) (end - pg) + (size_t) page;

    if (mprotect((void *) pg, len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect(RWX) failed @%p len=%lu (errno=%d) -- skip inline hook",
             target, (unsigned long) len, errno);
        return -1;
    }

    /* 构造 16 字节跳转块 */
    unsigned char code[16];
    code[0] = 0x50; code[1] = 0x00; code[2] = 0x00; code[3] = 0x58;  /* ldr x16,#8 */
    code[4] = 0x00; code[5] = 0x02; code[6] = 0x1F; code[7] = 0xD6;  /* br x16 */
    uint64_t d = (uint64_t) dest;
    for (int i = 0; i < 8; i++) {
        code[8 + i] = (unsigned char)((d >> (i * 8)) & 0xff);
    }

    /*
     * ★ 写入策略（修正 BUS_ADRALN）：
     *   目标函数地址可能只 4 字节对齐（实测 libsscronet.so+0x27a30c），
     *   用 __atomic_store_n(uint64_t*) 会因 8 字节对齐要求触发
     *   SIGBUS / BUS_ADRALN。
     *
     *   aarch64 上「4 字节对齐的 4 字节 store」本身就是原子的，
     *   所以拆成 4 次 4 字节写：
     *     1) 先写数据 [8..15]（dest 地址，两半）
     *     2) 再写指令 [4..7]（br x16）
     *     3) 最后写 [0..3]（ldr x16,#8）—— 这一步落地后跳转才生效
     *   保证任何时刻 CPU 取到的要么是原指令，要么是完整跳转。
     */
    volatile uint32_t *dst = (volatile uint32_t *) target;
    volatile uint32_t *src = (volatile uint32_t *) code;
    __asm__ __volatile__("dmb ish" ::: "memory");
    dst[2] = src[2];     /* .quad dest 低 4 字节 */
    dst[3] = src[3];     /* .quad dest 高 4 字节 */
    dst[1] = src[1];     /* br x16 */
    __asm__ __volatile__("dmb ish" ::: "memory");
    dst[0] = src[0];     /* ldr x16,#8 —— 生效点 */
    __asm__ __volatile__("dmb ish" ::: "memory");

    __builtin___clear_cache((char *) target, (char *) target + 16);
    mprotect((void *) pg, len, PROT_READ | PROT_EXEC);
    return 0;
}

/*
 * 尝试对所有已加载 so（含 dlopen 进来的）用 dlsym 找目标符号并 inline hook。
 * 注意：dlsym(RTLD_DEFAULT) 只找"全局可见"符号。
 *       对没导出的内部符号无能为力（那种只能靠 GOT hook）。
 */
static int try_inline_hook_global(void) {
    if (!g_inline_enabled) {
        return 0;
    }
    int hooked = 0;
    for (int i = 0; i < g_hook_count; i++) {
        if (g_hooks[i].hooked && g_hooks[i].original != NULL) {
            /* GOT 已经拦到了，跳过 */
        }
        void *addr = dlsym(RTLD_DEFAULT, g_hooks[i].name);
        if (!addr) {
            continue;
        }
        /* 检查是否已经 inline hook 过 */
        int found = 0;
        for (int k = 0; k < g_inline_count; k++) {
            if (g_inline[k].target == addr) {
                found = 1;
                break;
            }
        }
        if (found) {
            continue;
        }
        if (g_inline_count >= 16) {
            break;
        }
        inline_hook_t *h = &g_inline[g_inline_count];
        h->target = addr;
        h->replacement = g_hooks[i].replacement;
        memcpy(h->saved, addr, 16);
        if (write_abs_jump(addr, g_hooks[i].replacement) == 0) {
            h->installed = 1;
            g_inline_count++;
            hooked++;
            if (g_hooks[i].original == NULL) {
                g_hooks[i].original = addr;
            }
            g_hooks[i].hooked = 1;
            LOGI("inline-hooked (global): %s @ %p", g_hooks[i].name, addr);
        }
    }
    return hooked;
}

/* ====================================================================
 *  ★★★ 符号实体 inline hook（补齐 GOT hook 的盲区）
 *
 *  实测解析番茄的 so 得出符号分布：
 *    SSL_CTX_set_custom_verify    -> libttboringssl.so  @0x49dac   (DEFINED, 12B)
 *    SSL_set_verify               -> libttboringssl.so  @0x507dc   (DEFINED, 24B)
 *    SSL_CTX_set_verify           -> libttboringssl.so  @0x50810   (DEFINED, 12B)
 *    SSL_get_verify_result        -> libttboringssl.so  @0x50834   (DEFINED, 36B)
 *    X509_verify_cert             -> libttcrypto.so     @0xdab60   (DEFINED, 2752B)
 *    X509_STORE_CTX_get_error     -> libttcrypto.so     @0xdbe78   (DEFINED, 8B)
 *    Cronet_CertVerify_DoVerifyV2 -> libsscronet.so     @0x27a30c  (DEFINED, 16B)
 *    libsscronet.so 里的 SSL_CTX_set_custom_verify 是 UNDEF -> 运行时链接到 libttboringssl
 *
 *  结论：必须对这些 so 里的【函数实体】做 inline hook —— 内部调用不走 GOT。
 * ==================================================================== */

typedef struct {
    const char *name;
    const char *soname;
    uintptr_t sym_addr;
    size_t sym_size;
} sym_hit_t;

static sym_hit_t g_sym_hits[64];
static int g_sym_hit_count = 0;


/*
 * 用 DT_GNU_HASH 精确计算动态符号总数。
 *
 * 结构：
 *   nbuckets(u32), symoffset(u32), bloom_size(u32), bloom_shift(u32)
 *   bloom[bloom_size] (u64)
 *   buckets[nbuckets] (u32)
 *   chain[]           (u32)  -- 每个 bucket 链上的 (hash|1) 序列
 *
 * 最大符号索引 = symoffset + 最后一个 bucket 链长 - 1
 */
static uint32_t gnu_hash_symcount(uint64_t gnu_hash, uint64_t symtab) {
    if (!gnu_hash || !symtab) return 0;
    const uint32_t *h = (const uint32_t *) gnu_hash;
    uint32_t nbuckets   = h[0];
    uint32_t symoffset  = h[1];
    uint32_t bloom_size = h[2];
    if (nbuckets == 0 || bloom_size == 0 || nbuckets > 100000 || bloom_size > 100000) {
        return 0;
    }
    const uint64_t *bloom = (const uint64_t *) (h + 4);
    const uint32_t *buckets = (const uint32_t *) (bloom + bloom_size);
    const uint32_t *chain = buckets + nbuckets;

    /* 找最大 bucket 值 */
    uint32_t max_sym = 0;
    for (uint32_t i = 0; i < nbuckets; i++) {
        if (buckets[i] > max_sym) max_sym = buckets[i];
    }
    if (max_sym < symoffset) {
        return symoffset ? symoffset : 1;
    }
    /* 从 max_sym 沿 chain 走到链尾（最低位 = 1 表示结束） */
    uint32_t idx = max_sym - symoffset;
    uint32_t guard = 0;
    while (guard++ < 200000) {
        uint32_t v = chain[idx];
        if (v & 1u) {
            break;
        }
        idx++;
    }
    uint32_t count = symoffset + idx + 1;
    if (count > 200000) return 0;
    return count;
}

static int collect_symbols_in_so(const char *soname, uintptr_t base,
                                 const void *dyn, size_t dyn_size) {
    const uint64_t *d = (const uint64_t *) dyn;
    if (!d) return 0;

    uint64_t symtab = 0, strtab = 0, strsz = 0;
    uint64_t hash = 0, gnu_hash = 0;
    int cnt = (int) (dyn_size / 16);
    for (int i = 0; i < cnt; i++) {
        uint64_t tag = d[i * 2], val = d[i * 2 + 1];
        if (tag == DT_NULL_) break;
        if (tag == DT_SYMTAB_) symtab = val;
        else if (tag == DT_STRTAB_) strtab = val;
        else if (tag == DT_STRSZ_) strsz = val;
        else if (tag == DT_HASH_) hash = val;
        else if (tag == DT_GNU_HASH_) gnu_hash = val;
    }
    if (!symtab || !strtab) return 0;

    /* ★ 地址归一：d_val 可能是"相对基址偏移"，也可能是"已重定位的绝对地址" */
    if (symtab < base) symtab += base;
    if (strtab < base) strtab += base;
    if (hash && hash < base) hash += base;
    if (gnu_hash && gnu_hash < base) gnu_hash += base;

    /* ★ 用 DT_HASH 的 nchain 精确界定符号数量（最可靠） */
    /*
     * ★ 符号数量必须【精确】确定，不能猜 —— 猜会在越界读时触发
     *   SIGSEGV/SEGV_ACCERR（实测 libbinder.so 直接崩）。
     *
     * 优先 DT_HASH（SYSV hash）的 nchain：精确。
     * 其次 DT_GNU_HASH：需要解析 bucket/chain 才能算 symcount。
     * 两者都没有 -> 放弃（安全第一，GOT hook 已够用）。
     */
    uint32_t nsym_limit = 0;
    if (hash) {
        uint32_t nchain = *(uint32_t *) (hash + 4);
        if (nchain > 0 && nchain < 200000) {
            nsym_limit = nchain;
        }
    } else if (gnu_hash) {
        nsym_limit = gnu_hash_symcount(gnu_hash, symtab);
    }
    if (nsym_limit == 0) {
        LOGI("  [dynsym] %s: no DT_HASH/DT_GNU_HASH -> skip symbol scan",
             soname ? soname : "?");
        return 0;   /* ★ 安全退出，绝不越界 */
    }
    LOGI("  [dynsym] %s: symtab=%p strtab=%p strsz=%lu hash=%p limit=%u",
         soname ? soname : "?", (void *) symtab, (void *) strtab,
         (unsigned long) strsz, (void *) hash, nsym_limit);

    int found = 0;
    int dumped = 0;
    /* 先把 strtab 边界算出来，防止越界读 */
    uint64_t str_lo = strtab;
    uint64_t str_hi = strsz ? (strtab + strsz) : (strtab + 0x100000);

    for (uint32_t k = 0; k < nsym_limit; k++) {
        uint8_t *sym = (uint8_t *) (symtab + (uint64_t) k * 24);
        uint32_t st_name = *(uint32_t *) (sym);
        uint16_t st_shndx = *(uint16_t *) (sym + 6);
        uint64_t st_value = *(uint64_t *) (sym + 8);
        uint64_t st_size = *(uint64_t *) (sym + 16);

        if (st_name == 0) continue;
        uint64_t name_addr = strtab + st_name;
        if (name_addr < str_lo || name_addr >= str_hi) continue;
        if (st_shndx == 0 || st_value == 0) continue;
        const char *nm = (const char *) (strtab + st_name);
        if (!nm || !*nm) continue;

        /* ★ 诊断：dump 前 15 个符号名，用于验证 symtab/strtab 地址是否正确 */
        if (dumped < 15) {
            LOGI("    sym[%u] name=\"%s\" val=0x%lx shndx=%u",
                 k, nm, (unsigned long) st_value, (unsigned) st_shndx);
            dumped++;
        }

        for (int h = 0; h < g_hook_count; h++) {
            if (strcmp(nm, g_hooks[h].name) != 0) continue;
            if (st_shndx == 0 || st_value == 0) continue;
            if (g_sym_hit_count >= 64) return found;

            int dup = 0;
            for (int q = 0; q < g_sym_hit_count; q++) {
                if (g_sym_hits[q].sym_addr == base + st_value) {
                    dup = 1;
                    break;
                }
            }
            if (dup) break;

            sym_hit_t *hit = &g_sym_hits[g_sym_hit_count++];
            hit->name = nm;
            hit->soname = soname;
            hit->sym_addr = base + st_value;
            hit->sym_size = (size_t) st_size;
            LOGI("SYM: %s @ %s+0x%lx -> %p (size=%lu)",
                 nm, soname ? soname : "?", (unsigned long) st_value,
                 (void *) hit->sym_addr, (unsigned long) st_size);
            found++;
            break;
        }
    }
    return found;
}

static int inline_hook_collected(void) {
    if (!g_inline_enabled) {
        return 0;
    }
    int hooked = 0;
    for (int i = 0; i < g_sym_hit_count; i++) {
        sym_hit_t *hit = &g_sym_hits[i];
        for (int h = 0; h < g_hook_count; h++) {
            if (strcmp(hit->name, g_hooks[h].name) != 0) continue;

            /* ★ 已被 GOT hook 过的符号跳过 inline（避免 original 指向被改写代码） */
            if (g_hooks[h].hooked) break;

            int dup = 0;
            for (int k = 0; k < g_inline_count; k++) {
                if (g_inline[k].target == (void *) hit->sym_addr) {
                    dup = 1;
                    break;
                }
            }
            if (dup) break;
            if (g_inline_count >= 16) break;

            inline_hook_t *ih = &g_inline[g_inline_count];
            ih->target = (void *) hit->sym_addr;
            ih->replacement = g_hooks[h].replacement;
            memcpy(ih->saved, ih->target, 16);

            /* ★ 先建跳板：original 必须指向跳板，不能指向被改写的 target
             *   （否则 orig() 会再次跳进我们的 hook -> 无限递归 -> 卡死） */
            ih->trampoline = create_trampoline(ih->target, ih->saved);
            if (ih->trampoline == NULL) {
                LOGE("trampoline failed for %s -> skip", hit->name);
                break;
            }
            g_hooks[h].original = ih->trampoline;

            if (write_abs_jump(ih->target, g_hooks[h].replacement) == 0) {
                ih->installed = 1;
                g_inline_count++;
                hooked++;
                g_hooks[h].hooked = 1;
                LOGI("** inline-hooked (so entity): %s @ %p", hit->name, ih->target);
            } else {
                LOGE("inline hook FAILED: %s @ %p", hit->name, ih->target);
            }
            break;
        }
    }
    return hooked;
}

/*
 * 创建跳板（trampoline）：
 *   在别处分配可执行内存，放入【被覆盖的原始指令】+【跳回 target+16 的绝对跳转】。
 *   这样"调用原函数"不会再次进入我们自己的 hook（避免无限递归 -> 网络卡死）。
 */
static void *create_trampoline(void *target, const unsigned char *saved) {
    long page = sysconf(_SC_PAGESIZE);
    void *mem = mmap(NULL, (size_t) page, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        LOGE("trampoline mmap failed (errno=%d)", errno);
        return NULL;
    }
    unsigned char *p = (unsigned char *) mem;
    memcpy(p, saved, 16);
    uint64_t back = (uint64_t) ((uintptr_t) target + 16);
    p[16] = 0x50; p[17] = 0x00; p[18] = 0x00; p[19] = 0x58;
    p[20] = 0x00; p[21] = 0x02; p[22] = 0x1F; p[23] = 0xD6;
    for (int i = 0; i < 8; i++) {
        p[24 + i] = (unsigned char) ((back >> (i * 8)) & 0xff);
    }
    __builtin___clear_cache((char *) mem, (char *) mem + 32);
    LOGI("trampoline created: %p for target=%p", mem, target);
    return mem;
}

int hook_so_by_dynamic(so_ctx_t *ctx) {
    const uint64_t *dyn = (const uint64_t *) ctx->dyn;
    if (!dyn) return 0;

    /* dt_val 在 64 位 ELF 里存的是"虚拟地址（相对 base）"，
     * 但 PT_DYNAMIC 段的地址是绝对的（dlpi_addr 已加过）。
     * 实测 Android linker 给的是相对 base 的偏移。 */
    uint64_t strtab = 0, symtab = 0, jmprel = 0, pltrelsz = 0, rela = 0, relasz = 0;
    int cnt = (int) (ctx->dyn_size / 16);

    for (int i = 0; i < cnt; i++) {
        uint64_t tag = dyn[i * 2];
        uint64_t val = dyn[i * 2 + 1];
        if (tag == DT_NULL_) break;
        switch (tag) {
            case DT_STRTAB_: strtab = val; break;
            case DT_SYMTAB_: symtab = val; break;
            case DT_JMPREL_: jmprel = val; break;
            case DT_PLTRELSZ_: pltrelsz = val; break;
            case DT_RELA_: rela = val; break;
            case DT_RELASZ_: relasz = val; break;
            default: break;
        }
    }
    if (!strtab || !symtab) return 0;

    /* 判断 val 是绝对地址还是偏移 */
    uint64_t base = ctx->base;
    if (strtab < base) strtab += base;
    if (symtab < base) symtab += base;

    int hooked = 0;

    /* 处理一段 rela */
    #define PROC_RELA(_addr, _size) do {                                        \
        uint64_t a = (_addr); uint64_t s = (_size);                             \
        if (a && s) {                                                           \
            if (a < base) a += base;                                            \
            size_t n = (size_t)(s / 24);                                        \
            hooked += hook_rela_entries((void*)a, n, symtab, strtab, base, ctx);\
        }                                                                       \
    } while (0)

    PROC_RELA(jmprel, pltrelsz);
    PROC_RELA(rela, relasz);
    #undef PROC_RELA

    return hooked;
}

/* 处理具体的 rela 表 */
int hook_rela_entries(void *rela_addr, size_t n, uint64_t symtab, uint64_t strtab,
                      uint64_t base, so_ctx_t *ctx);

int hook_rela_entries(void *rela_addr, size_t n, uint64_t symtab, uint64_t strtab,
                      uint64_t base, so_ctx_t *ctx) {
    int hooked = 0;
    (void) ctx;
    uint8_t *p = (uint8_t *) rela_addr;
    long page = sysconf(_SC_PAGESIZE);

    for (size_t k = 0; k < n; k++) {
        uint8_t *e = p + k * 24;
        uint64_t r_offset = *(uint64_t *) (e);
        uint64_t r_info = *(uint64_t *) (e + 8);
        uint32_t r_type = (uint32_t) (r_info & 0xffffffff);
        uint32_t r_sym = (uint32_t) (r_info >> 32);

        if (r_type != R_AARCH64_GLOB_DAT_ && r_type != R_AARCH64_JUMP_SLOT_
            && r_type != R_X86_64_GLOB_DAT_ && r_type != R_X86_64_JUMP_SLOT_
            && r_type != R_AARCH64_ABS64_ && r_type != R_X86_64_64_) {
            continue;
        }

        uint8_t *sym = (uint8_t *) (symtab + r_sym * 24);
        uint32_t st_name = *(uint32_t *) (sym);
        if (st_name == 0) continue;
        const char *sname = (const char *) (strtab + st_name);
        if (!sname || !*sname) continue;

        for (int h = 0; h < g_hook_count; h++) {
            if (strcmp(sname, g_hooks[h].name) != 0) continue;

            uintptr_t *got = (uintptr_t *) (base + r_offset);
            uintptr_t pg = (uintptr_t) got & ~(uintptr_t) (page - 1);
            uintptr_t gend = ((uintptr_t) got + sizeof(void *) - 1) & ~(uintptr_t)(page - 1);
            size_t glen = (size_t) (gend - pg) + (size_t) page;

            if (mprotect((void *) pg, glen, PROT_READ | PROT_WRITE) != 0) {
                continue;
            }
            if (g_hooks[h].original == NULL) {
                g_hooks[h].original = (void *) (*got);
            }
            *got = (uintptr_t) g_hooks[h].replacement;
            g_hooks[h].hooked = 1;
            hooked++;
            LOGI("GOT hooked: %s (orig=%p)", sname, g_hooks[h].original);
            mprotect((void *) pg, glen, PROT_READ);
            break;
        }
    }
    return hooked;
}


/* ====================================================================
 *  ★★ dlopen 拦截 —— 解决 "hook 太晚" 的问题
 *
 *  网络 so（libsscronet / libttboringssl / libquick）是运行时 dlopen 进来的。
 *  如果在 onPackageReady（App 启动 2 秒后）才扫，它们的 SSL_CTX 早就建好了，
 *  SSL_CTX_set_custom_verify 的回调也注册完了 —— 再 hook 函数头也没用。
 *
 *  解法：拦截 libdl.so / libc.so 的 dlopen / android_dlopen_ext / dlopen_ext，
 *        每次 so 加载完成【立刻】跑一次全量扫描 + inline hook。
 * ==================================================================== */

typedef void *(*dlopen_t)(const char *, int);
typedef void *(*android_dlopen_ext_t)(const char *, int, const void *);

static dlopen_t g_orig_dlopen = NULL;
static android_dlopen_ext_t g_orig_android_dlopen_ext = NULL;
static volatile int g_in_dlopen_hook = 0;

/* 重新扫描并 inline hook（dlopen 后调用） */
static void rescan_and_hook(void) {
    if (g_in_dlopen_hook) return;      /* 防重入 */
    g_in_dlopen_hook = 1;
    dl_iterate_phdr(phdr_cb, NULL);
    inline_hook_collected();
    try_inline_hook_global();
    g_in_dlopen_hook = 0;
}

/*
 * ★ 注意：不要 hook dlopen / android_dlopen_ext！
 *
 * 它们是多线程高频热点函数，inline hook 改写首个指令块时，
 * 其它线程可能正在执行该处的指令 -> SIGSEGV/SEGV_ACCERR（实测必崩）。
 *
 * 替代方案：watchdog 线程高频轮询 + JNI_OnLoad/Linker 完成回调。
 */


static void install_dlopen_hooks(void) {
    /* 刻意留空：见上方说明 */
}

/* 启动一个后台线程，持续扫描（兜底 dlopen 拦截失效的情况） */
static void *watchdog_thread(void *arg) {
    (void) arg;
    int last_total = -1;
    for (int i = 0; i < 1200; i++) {          /* 1200 x 50ms = 60s */
        usleep(50 * 1000);
        if (g_in_dlopen_hook) continue;
        if (!g_inline_enabled) continue;
        g_in_dlopen_hook = 1;
        int before_syms = g_sym_hit_count;
        int before_inline = g_inline_count;
        dl_iterate_phdr(phdr_cb, NULL);
        /* ★ 只有发现了新符号才做 inline hook（避免反复改写代码段） */
        if (g_sym_hit_count > before_syms) {
            inline_hook_collected();
        }
        int total = g_inline_count;
        g_in_dlopen_hook = 0;
        if (total != last_total) {
            LOGI("[watchdog] pass %d: new_syms=%d total_inline=%d",
                 i, g_sym_hit_count - before_syms, total);
            last_total = total;
        }
        /* 全部 9 个目标都 hook 上了就继续跑，后面可能还有新 so */
    }
    LOGI("[watchdog] exit");
    return NULL;
}

/* ====================================================================
 *  JNI 入口
 * ==================================================================== */

static int g_installed = 0;

JNIEXPORT jint JNICALL
Java_com_sslkit_native_1layer_NativeHookInstaller_nativeInstall(JNIEnv *env, jclass clazz) {
    (void) env; (void) clazz;
    pthread_mutex_lock(&g_lock);
    if (g_installed) {
        pthread_mutex_unlock(&g_lock);
        return 0;
    }
    g_installed = 1;

    register_hooks();
    dl_iterate_phdr(phdr_cb, NULL);
    int inline_n = inline_hook_collected();
    inline_n += try_inline_hook_global();

    int total = 0;
    for (int i = 0; i < g_hook_count; i++) {
        if (g_hooks[i].hooked) total++;
    }
    LOGI("native hook installed: %d symbols hooked (%d via inline)", total, inline_n);
    pthread_mutex_unlock(&g_lock);
    return total;
}

JNIEXPORT jint JNICALL
Java_com_sslkit_native_1layer_NativeHookInstaller_nativeRescan(JNIEnv *env, jclass clazz) {
    (void) env; (void) clazz;
    pthread_mutex_lock(&g_lock);
    register_hooks();
    dl_iterate_phdr(phdr_cb, NULL);
    inline_hook_collected();
    try_inline_hook_global();
    int total = 0;
    for (int i = 0; i < g_hook_count; i++) {
        if (g_hooks[i].hooked) total++;
    }
    pthread_mutex_unlock(&g_lock);
    return total;
}

JNIEXPORT jstring JNICALL
Java_com_sslkit_native_1layer_NativeHookInstaller_nativeStats(JNIEnv *env, jclass clazz) {
    (void) clazz;
    char buf[1024];
    snprintf(buf, sizeof(buf),
             "custom_verify=%d, x509_verify=%d, verify_result=%d, cronet_do_verify=%d",
             g_stat_custom_verify, g_stat_x509_verify,
             g_stat_verify_result, g_stat_cronet_do_verify);
    return (*env)->NewStringUTF(env, buf);
}

JNIEXPORT jstring JNICALL
Java_com_sslkit_native_1layer_NativeHookInstaller_nativeVersion(JNIEnv *env, jclass clazz) {
    (void) clazz;
    return (*env)->NewStringUTF(env, "SSLKit-native 1.0.0");
}

/* 构造函数：so 加载时自动 hook 一次 */
/* 读 Java 传进来的开关（通过 __system_property_get） */
extern int __system_property_get(const char *name, char *value);

__attribute__((constructor))
static void sslkit_ctor(void) {
    char buf[8];
    buf[0] = 0;
    if (__system_property_get("debug.sslkit.inline", buf) > 0 && buf[0] == '1') {
        g_inline_enabled = 1;
    }
    LOGI("libsslkit.so loaded, inline_hook=%s", g_inline_enabled ? "ON" : "OFF");
    register_hooks();
    dl_iterate_phdr(phdr_cb, NULL);
    inline_hook_collected();
    try_inline_hook_global();

    /* ★ 拦截 dlopen，新 so 加载后立刻 hook */
    install_dlopen_hooks();

    /* ★ watchdog 线程兜底（dlopen 拦截可能被 linker 内部路径绕过） */
    pthread_t t;
    if (pthread_create(&t, NULL, watchdog_thread, NULL) == 0) {
        pthread_detach(t);
        LOGI("[watchdog] started (300 x 200ms)");
    }
}
