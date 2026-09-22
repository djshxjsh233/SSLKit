package com.sslkit.cronet;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;
import com.sslkit.native_layer.NativeHookInstaller;

/**
 * ★ Cronet 专杀（Native 侧）。
 *
 * Java 侧的 CronetCertResultHook 只管 Java 回调结果；
 * 真正的 TLS 校验发生在 libsscronet.so 里（BoringSSL 静态链）。
 *
 * 本类确保：
 *   1. libsscronet.so 被加载后立刻做 GOT hook
 *   2. Cronet_CertVerify_DoVerifyV2 / Cronet_VerifyResult_* 被拦
 *      （由 libsslkit.so 的符号表覆盖）
 *
 * 检测：读 /proc/self/maps 找 cronet 特征 so。
 */
public class CronetNativeHook extends BaseHook {

    /** 已知的 Cronet 系 so 特征 */
    private static final String[] CRONET_SO_HINTS = {
            "libsscronet.so",       // 字节 / TikTok / 番茄
            "libcronet.so",         // Google 官方
            "libttcronet.so",       // 头条系
            "libcronet3.so",
            "libquic.so"            // 部分自研
    };

    public CronetNativeHook(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    @Override
    public void install() {
        String found = detectCronetSo();
        if (found == null) {
            com.sslkit.core.HookLogger.skip("Cronet.Native", "no-cronet-so");
            return;
        }
        module.info("[SSLKit] ★ Cronet so detected: " + found);

        // 确保 native 层已加载（Cronet 的 hook 符号在 libsslkit.so 里）
        tryHook("Cronet.Native.ensureNative", new HookAction() {
            @Override
            public void run() throws Throwable {
                if (!NativeHookInstaller.isLoaded()) {
                    // 尝试加载
                    try {
                        System.loadLibrary("sslkit");
                    } catch (Throwable t) {
                        throw new IllegalStateException("native load failed", t);
                    }
                }
                int n = NativeHookInstaller.rescan();
                module.info("[SSLKit] Cronet rescan -> " + n + " symbols");
            }
        });
    }

    /** 读 /proc/self/maps 找 Cronet so */
    private String detectCronetSo() {
        try {
            java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.FileReader("/proc/self/maps"));
            String line;
            while ((line = br.readLine()) != null) {
                for (String hint : CRONET_SO_HINTS) {
                    int idx = line.indexOf(hint);
                    if (idx >= 0) {
                        br.close();
                        // 提取完整路径
                        String[] parts = line.trim().split("\\s+");
                        return parts.length > 5 ? parts[parts.length - 1] : hint;
                    }
                }
            }
            br.close();
        } catch (Throwable ignored) {
        }
        return null;
    }
}
