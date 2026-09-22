package com.sslkit;

/**
 * 模块配置。
 *
 * 默认全开 —— 通用模块的目标是"装上就生效"。
 * 用户可在 App 界面里逐层开关。
 */
public final class Config {

    // ---- 分层开关 ----
    /** L1: Java 层（SSLContext / TrustManager / OkHttp / Conscrypt / NSC ...） */
    public static boolean L1_JAVA = true;
    /** L2: Native 层（BoringSSL / OpenSSL 通用符号 hook） */
    public static boolean L2_NATIVE = true;
    /** L3: Dart / Flutter 层（依赖 L2） */
    public static boolean L3_DART = true;
    /** L4: WebView / H5 层 */
    public static boolean L4_WEBVIEW = true;
    /**
     * L5: 反检测层（代理 / VPN 伪装）。
     *
     * ★ 默认关闭（实测教训）：
     *   VPN 抓包模式下 App 的流量【本来就必须】走代理。
     *   把代理伪装成"无代理"会让 App 直连 → 绕过抓包 → 抓不到数据。
     *   反检测只适用于"App 检测到代理就拒连"的场景，需用户显式开启。
     */
    public static boolean L5_ANTIDETECT = false;

    // ---- 细项开关 ----
    /** 全量类扫描（FULL 更通用但更慢；FAST 只 hook 已知类名） */
    public static boolean FULL_CLASS_SCAN = true;
    /** OkHttp 混淆版反射定位 */
    public static boolean OKHTTP_OBFUSCATED = true;
    /** Cronet 专杀（字节 / Google 系） */
    public static boolean CRONET_KILL = true;
    /** 详细日志 */
    public static boolean VERBOSE = true;

    // ---- 类扫描参数 ----
    /** 类名过滤关键词（大小写不敏感） */
    public static final String[] SCAN_KEYWORDS = {
            "Trust", "Pinner", "Pinning", "Verify", "Verifier",
            "Cert", "X509", "Ssl", "SSL", "Tls", "TLS",
            "Https", "Hostname", "SecureSocket", "Cronet"
    };

    /** 类名白名单前缀（跳过，避免误伤 / 性能） */
    public static final String[] SCAN_EXCLUDE_PREFIX = {
            "java.", "javax.", "kotlin.", "kotlinx.",
            "android.", "androidx.", "com.android.",
            "dalvik.", "sun.", "org.apache.harmony.",
            // 渲染/图形，避免 signal 6
            "android.opengl.", "com.google.android.gles.",
            // 我们自己的类
            "com.sslkit.",
            // 常见无关大库
            "org.json.", "com.google.gson.", "org.xml.", "com.google.protobuf."
    };

    /** native hook 排除的 so 名（渲染库，hook 会 abort） */
    public static final String[] SO_EXCLUDE = {
            "vulkan", "adreno", "mali", "gralloc", "libegl", "libgles",
            "libhwui", "libgui", "libui", "libllvm", "librs", "libgsl",
            "libdmabufheap", "libhardware", "/vendor/", "libsslkit",
            "libc.so", "libm.so", "libdl.so", "libart", "libnativehelper"
    };

    /**
     * 从模块的远程 SharedPreferences 读用户配置（模块界面里改的开关）。
     * LSPosed 的 getRemotePreferences(name) 可跨进程读模块自己的 prefs。
     */
    public static void loadFromPrefs(Object module) {
        try {
            android.content.SharedPreferences sp = null;
            if (module instanceof io.github.libxposed.api.XposedInterfaceWrapper) {
                sp = ((io.github.libxposed.api.XposedInterfaceWrapper) module)
                        .getRemotePreferences("sslkit_config");
            }
            if (sp == null) {
                return;
            }
            L1_JAVA = sp.getBoolean("l1", L1_JAVA);
            L2_NATIVE = sp.getBoolean("l2", L2_NATIVE);
            L3_DART = sp.getBoolean("l3", L3_DART);
            L4_WEBVIEW = sp.getBoolean("l4", L4_WEBVIEW);
            L5_ANTIDETECT = sp.getBoolean("l5", L5_ANTIDETECT);
            FULL_CLASS_SCAN = sp.getBoolean("scan", FULL_CLASS_SCAN);
            CRONET_KILL = sp.getBoolean("cronet", CRONET_KILL);
            OKHTTP_OBFUSCATED = sp.getBoolean("okobf", OKHTTP_OBFUSCATED);
            VERBOSE = sp.getBoolean("verbose", VERBOSE);
        } catch (Throwable ignored) {
        }
    }

    private Config() {
    }
}
