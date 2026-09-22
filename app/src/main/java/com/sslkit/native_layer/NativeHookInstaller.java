package com.sslkit.native_layer;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;
import com.sslkit.core.HookLogger;

/**
 * L2 · Native hook 安装器。
 *
 * 加载 libsslkit.so，让它遍历所有已加载的 so 并做 GOT hook。
 */
public class NativeHookInstaller extends BaseHook {

    private static boolean sLoaded = false;
    private static boolean sLoadTried = false;

    public NativeHookInstaller(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    /** 由 native 侧调用 */
    public static native int nativeInstall();

    /** 动态 so 加载后重新扫描 */
    public static native int nativeRescan();

    /** 命中统计 */
    public static native String nativeStats();

    /** native 版本 */
    public static native String nativeVersion();

    @Override
    public void install() {
        // 保证系统库先加载（native 侧 hook 才能覆盖 dlopen 路径）
        try {
            System.loadLibrary("c");
            System.loadLibrary("log");
        } catch (Throwable ignored) {
        }
        // 触发目标进程里 BoringSSL 的加载
        try {
            Class.forName("com.android.org.conscrypt.OpenSSLSocketFactoryImpl", false, cl);
        } catch (Throwable ignored) {
        }
        try {
            Class.forName("javax.net.ssl.SSLContext", false, cl);
        } catch (Throwable ignored) {
        }

        if (!loadLibrary()) {
            HookLogger.skip("L2.Native", "so-load-failed");
            return;
        }
        // 先 rescan 一次（确保系统 ssl 库已加载时也能拦到）
        try {
            nativeRescan();
        } catch (Throwable ignored) {
        }
        tryHook("L2.Native.install", new HookAction() {
            @Override
            public void run() throws Throwable {
                int n = nativeInstall();
                module.info("[SSLKit] native hooks installed: " + n + " symbols");
            }
        });

        // 打印 native 版本
        tryHook("L2.Native.version", new HookAction() {
            @Override
            public void run() throws Throwable {
                module.info("[SSLKit] " + nativeVersion());
            }
        });
    }

    private synchronized boolean loadLibrary() {
        if (sLoaded) {
            return true;
        }
        if (sLoadTried && !sLoaded) {
            // 只尝试一次，避免刷屏
            return false;
        }
        sLoadTried = true;
        try {
            System.loadLibrary("sslkit");
            sLoaded = true;
            module.info("[SSLKit] libsslkit.so loaded (auto-hook on load)");
            return true;
        } catch (Throwable t) {
            module.logError("[SSLKit] load libsslkit.so failed", t);
            return false;
        }
    }

    public static boolean isLoaded() {
        return sLoaded;
    }

    /** 供 SoRescanner 调用 */
    public static int rescan() {
        if (!sLoaded) {
            return -1;
        }
        try {
            return nativeRescan();
        } catch (Throwable t) {
            return -2;
        }
    }

    public static String stats() {
        if (!sLoaded) {
            return "(native not loaded)";
        }
        try {
            return nativeStats();
        } catch (Throwable t) {
            return "(stats error)";
        }
    }
}
