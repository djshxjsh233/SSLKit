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
    __sync_fetch_and_add(&g_stat_custom_verify, 1);
    LOGI("SSL_CTX_set_custom_verify called (mode=%d) -> replaced with always-OK", mode);
    /* 重新调用原函数，但传入我们的回调 */
    /* 原函数原型: void SSL_CTX_set_custom_verify(SSL_CTX*, int mode, cb) */
    typedef void (*fn_t)(void *, int, void *);
    fn_t orig = (fn_t) find_original("SSL_CTX_set_custom_verify");
    if (orig) {
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

/* 前向声明 */
static int collect_symbols_in_so(const char *soname, uintptr_t base,
                                 const void *dyn, size_t dyn_size);
static int inline_hook_collected(void);
static int write_abs_jump(void *target, void *dest);
static int try_inline_hook_global(void);

static void register_hooks(void) {
    int i = 0;
    g_hooks[i].name = "SSL_CTX_set_custom_verify";
    g_hooks[i++].replacement = (void *) sslkit_SSL_CTX_set_custom_verify;

    g_hooks[i].name = "X509_verify_cert";
    g_hooks[i++].replacement = (void *) sslkit_X509_verify_cert;

    g_hooks[i].name = "SSL_get_verify_result";
    g_hooks[i++].replacement = (void *) sslkit_SSL_get_verify_result;

    g_hooks[i].name = "SSL_set_verify";
    g_hooks[i++].replacement = (void *) sslkit_SSL_set_verify;

    g_hooks[i].name = "SSL_CTX_set_verify";
    g_hooks[i++].replacement = (void *) sslkit_SSL_CTX_set_verify;

    g_hooks[i].name = "X509_STORE_CTX_get_error";
    g_hooks[i++].replacement = (void *) sslkit_X509_STORE_CTX_get_error;

    /* Cronet */
    g_hooks[i].name = "Cronet_CertVerify_DoVerifyV2";
    g_hooks[i++].replacement = (void *) sslkit_Cronet_CertVerify_DoVerifyV2;

    g_hooks[i].name = "Cronet_VerifyResult_is_issued_by_known_root_set";
    g_hooks[i++].replacement = (void *) sslkit_Cronet_VerifyResult_is_issued_by_known_root_set;

    g_hooks[i].name = "Cronet_EngineParams_public_key_pins_add";
    g_hooks[i++].replacement = (void *) sslkit_Cronet_EngineParams_public_key_pins_add;

    g_hook_count = i;
    LOGI("registered %d target symbols", g_hook_count);
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
                uintptr_t pg = (uintptr_t) got & ~(page - 1);
                if (mprotect((void *) pg, (size_t) page * 2,
                             PROT_READ | PROT_WRITE) != 0) {
                    LOGE("mprotect fail @%p", got);
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

                /* 恢复只读（只读+可执行） */
                mprotect((void *) pg, (size_t) page * 2, PROT_READ);
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
    int patched;      /* 是否已 patch 到 stub */
    unsigned char *stub; /* 跳板：保存原指令 + 跳回 */
} inline_hook_t;

static inline_hook_t g_inline[16];
static int g_inline_count = 0;

/* 在目标地址写入绝对跳转：ldr x16,#8; br x16; .quad dest */
static int write_abs_jump(void *target, void *dest) {
    long page = sysconf(_SC_PAGESIZE);
    uintptr_t pg = (uintptr_t) target & ~(uintptr_t)(page - 1);
    if (mprotect((void *) pg, (size_t) page * 2, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return -1;
    }
    unsigned char code[16];
    /* ldr x16, #8   => 0x58000050 (little endian) */
    code[0] = 0x50; code[1] = 0x00; code[2] = 0x00; code[3] = 0x58;
    /* br x16        => 0xD61F0200 */
    code[4] = 0x00; code[5] = 0x02; code[6] = 0x1F; code[7] = 0xD6;
    /* .quad dest */
    uint64_t d = (uint64_t) dest;
    for (int i = 0; i < 8; i++) {
        code[8 + i] = (unsigned char)((d >> (i * 8)) & 0xff);
    }
    memcpy(target, code, 16);
    __builtin___clear_cache((char *) target, (char *) target + 16);
    mprotect((void *) pg, (size_t) page * 2, PROT_READ | PROT_EXEC);
    return 0;
}

/*
 * 尝试对所有已加载 so（含 dlopen 进来的）用 dlsym 找目标符号并 inline hook。
 * 注意：dlsym(RTLD_DEFAULT) 只找"全局可见"符号。
 *       对没导出的内部符号无能为力（那种只能靠 GOT hook）。
 */
static int try_inline_hook_global(void) {
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
    uint32_t nsym_limit = 40000;
    if (hash) {
        uint32_t nchain = *(uint32_t *) (hash + 4);   /* hash[1] = nchain */
        if (nchain > 0 && nchain < 200000) {
            nsym_limit = nchain;
        }
    } else if (gnu_hash && strsz) {
        /* GNU hash 没直接给 nchain，用保守上限 */
        nsym_limit = 40000;
    }
    LOGI("  [dynsym] %s: symtab=%p strtab=%p strsz=%lu hash=%p limit=%u",
         soname ? soname : "?", (void *) symtab, (void *) strtab,
         (unsigned long) strsz, (void *) hash, nsym_limit);

    int found = 0;
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
    int hooked = 0;
    for (int i = 0; i < g_sym_hit_count; i++) {
        sym_hit_t *hit = &g_sym_hits[i];
        for (int h = 0; h < g_hook_count; h++) {
            if (strcmp(hit->name, g_hooks[h].name) != 0) continue;

            int dup = 0;
            for (int k = 0; k < g_inline_count; k++) {
                if (g_inline[k].target == (void *) hit->sym_addr) {
                    dup = 1;
                    break;
                }
            }
            if (dup) break;
            if (g_inline_count >= 16) break;

            if (g_hooks[h].original == NULL) {
                g_hooks[h].original = (void *) hit->sym_addr;
            }

            inline_hook_t *ih = &g_inline[g_inline_count];
            ih->target = (void *) hit->sym_addr;
            ih->replacement = g_hooks[h].replacement;
            memcpy(ih->saved, ih->target, 16);
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

            if (mprotect((void *) pg, (size_t) page * 2,
                         PROT_READ | PROT_WRITE) != 0) {
                continue;
            }
            if (g_hooks[h].original == NULL) {
                g_hooks[h].original = (void *) (*got);
            }
            *got = (uintptr_t) g_hooks[h].replacement;
            g_hooks[h].hooked = 1;
            hooked++;
            LOGI("GOT hooked: %s (orig=%p)", sname, g_hooks[h].original);
            mprotect((void *) pg, (size_t) page * 2, PROT_READ);
            break;
        }
    }
    return hooked;
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
__attribute__((constructor))
static void sslkit_ctor(void) {
    LOGI("libsslkit.so loaded, auto-installing hooks");
    register_hooks();
    dl_iterate_phdr(phdr_cb, NULL);
    inline_hook_collected();
    try_inline_hook_global();
}
