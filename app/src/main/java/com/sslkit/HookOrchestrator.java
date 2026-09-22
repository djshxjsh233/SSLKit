package com.sslkit;

import com.sslkit.anti.ProxyMaskHook;
import com.sslkit.anti.VpnMaskHook;
import com.sslkit.core.ClassScanner;
import com.sslkit.core.HookLogger;
import com.sslkit.core.SSLFactory;
import com.sslkit.cronet.CronetCertResultHook;
import com.sslkit.cronet.CronetNativeHook;
import com.sslkit.dart.FlutterDetect;
import com.sslkit.java_layer.ApacheHook;
import com.sslkit.java_layer.ConscryptHook;
import com.sslkit.java_layer.ExtTrustManagerHook;
import com.sslkit.java_layer.GenericScanHook;
import com.sslkit.java_layer.NSCtrustHook;
import com.sslkit.java_layer.NettyGrpcHook;
import com.sslkit.java_layer.OkHttpHook;
import com.sslkit.java_layer.SSLContextHook;
import com.sslkit.java_layer.TrustManagerHook;
import com.sslkit.native_layer.NativeHookInstaller;
import com.sslkit.native_layer.SoRescanner;
import com.sslkit.web.WebViewHook;

/**
 * Hook 总调度。
 *
 * 职责：
 *  1. 按配置依次启用各层
 *  2. 每层独立 try/catch（一层失败不影响其它层）
 *  3. 统一日志与命中统计
 */
public class HookOrchestrator {

    private final MainHook module;
    private final ClassLoader cl;
    private final String packageName;

    public HookOrchestrator(MainHook module, ClassLoader cl, String packageName) {
        this.module = module;
        this.cl = cl;
        this.packageName = packageName;
    }

    public void run() {
        long t0 = System.currentTimeMillis();
        Config.loadFromPrefs(module);
        HookLogger.reset(packageName);
        module.info("[SSLKit] ===== start hook: " + packageName + " =====");

        // ---------- L1: Java 层 ----------
        if (Config.L1_JAVA) {
            runLayer("L1.SSLContextHook", new Runnable() {
                public void run() { new SSLContextHook(module, cl).install(); }
            });
            runLayer("L1.TrustManagerHook", new Runnable() {
                public void run() { new TrustManagerHook(module, cl).install(); }
            });
            runLayer("L1.ExtTrustManagerHook", new Runnable() {
                public void run() { new ExtTrustManagerHook(module, cl).install(); }
            });
            runLayer("L1.ConscryptHook", new Runnable() {
                public void run() { new ConscryptHook(module, cl).install(); }
            });
            runLayer("L1.NetworkSecurityHook", new Runnable() {
                public void run() { new NSCtrustHook(module, cl).install(); }
            });
            runLayer("L1.OkHttpHook", new Runnable() {
                public void run() { new OkHttpHook(module, cl).install(); }
            });
            runLayer("L1.ApacheHook", new Runnable() {
                public void run() { new ApacheHook(module, cl).install(); }
            });
            runLayer("L1.NettyGrpcHook", new Runnable() {
                public void run() { new NettyGrpcHook(module, cl).install(); }
            });
        }

        // ---------- L4: WebView ----------
        if (Config.L4_WEBVIEW) {
            runLayer("L4.WebViewHook", new Runnable() {
                public void run() { new WebViewHook(module, cl).install(); }
            });
        }

        // ---------- L5: 反检测 ----------
        if (Config.L5_ANTIDETECT) {
            runLayer("L5.ProxyMaskHook", new Runnable() {
                public void run() { new ProxyMaskHook(module, cl).install(); }
            });
            runLayer("L5.VpnMaskHook", new Runnable() {
                public void run() { new VpnMaskHook(module, cl).install(); }
            });
        }

        // ---------- L2: Native 层 ----------
        if (Config.L2_NATIVE) {
            runLayer("L2.NativeHookInstaller", new Runnable() {
                public void run() { new NativeHookInstaller(module, cl).install(); }
            });
            runLayer("L2.SoRescanner", new Runnable() {
                public void run() { new SoRescanner(module, cl).install(); }
            });
        }

        // ---------- Cronet 专杀 ----------
        if (Config.CRONET_KILL) {
            runLayer("Cronet.CertResultHook", new Runnable() {
                public void run() { new CronetCertResultHook(module, cl).install(); }
            });
            runLayer("Cronet.NativeHook", new Runnable() {
                public void run() { new CronetNativeHook(module, cl).install(); }
            });
        }

        // ---------- L3: Dart / Flutter ----------
        if (Config.L3_DART) {
            runLayer("L3.FlutterDetect", new Runnable() {
                public void run() { new FlutterDetect(module, cl).install(); }
            });
        }

        // ---------- 全量类扫描（放最后，覆盖前面漏掉的） ----------
        if (Config.FULL_CLASS_SCAN) {
            runLayer("GenericScanHook", new Runnable() {
                public void run() { new GenericScanHook(module, cl, ClassScanner.scan(cl)).install(); }
            });
        }

        long cost = System.currentTimeMillis() - t0;
        module.info("[SSLKit] ===== done in " + cost + "ms =====");
        module.info(HookLogger.summary());
        SSLFactory.warmUp();
    }

    private void runLayer(String name, Runnable r) {
        try {
            r.run();
        } catch (Throwable t) {
            module.logError("[SSLKit] layer failed: " + name, t);
            HookLogger.fail(name, t);
        }
    }
}
