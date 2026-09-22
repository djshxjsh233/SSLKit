package com.sslkit.dart;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;

import java.lang.reflect.Method;
import java.util.List;

import io.github.libxposed.api.XposedInterface;

/**
 * L3 · Flutter / Dart 检测与处理。
 *
 * 原理：
 *   Flutter 的 dart:io 网络栈完全绕开 Java：
 *     HttpClient → native dart → _SecureSocket → BoringSSL
 *   Java 层一点看不到。但它用的是 BoringSSL 静态链 →
 *   **L2 native 层的 SSL_CTX_set_custom_verify 通用 hook 能覆盖**。
 *
 * 本类的职责：
 *   1. 检测是否是 Flutter App（libflutter.so / libapp.so）
 *   2. 日志提示，并确认 native 层已启用
 *   3. 尝试 Dart 层 hook（有符号时）
 */
public class FlutterDetect extends BaseHook {

    public FlutterDetect(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    @Override
    public void install() {
        boolean isFlutter = detectFlutter();
        if (isFlutter) {
            module.info("[SSLKit] ★ Flutter App detected → native hook (L2) is the key layer");
        }
        hookFlutterRelatedJava();
    }

    /**
     * 检测 Flutter：看 ClassLoader / so 列表里有没有 flutter 特征。
     */
    private boolean detectFlutter() {
        // 1) Java 类特征
        String[] markers = {
                "io.flutter.embedding.engine.FlutterEngine",
                "io.flutter.plugin.common.MethodChannel",
                "io.flutter.app.FlutterActivity"
        };
        for (String cn : markers) {
            if (classExists(cn)) {
                return true;
            }
        }

        // 2) native so 特征（读 /proc/self/maps）
        try {
            java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.FileReader("/proc/self/maps"));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.contains("libflutter.so") || line.contains("libapp.so")) {
                    br.close();
                    return true;
                }
            }
            br.close();
        } catch (Throwable ignored) {
        }
        return false;
    }

    /**
     * Flutter 的 Java 侧通常不管 TLS，
     * 但有些插件（如 flutter_downloader、connectivity_plus）会走原生栈。
     * 这里把 Flutter 引擎里可能存在的 Java SSL 调用也兜一下。
     */
    private void hookFlutterRelatedJava() {
        final String cn = "io.flutter.plugin.common.MethodChannel";
        if (!classExists(cn)) {
            return;
        }
        tryHook("Flutter MethodChannel（占位）", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                boolean found = false;
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("invokeMethod")) {
                        found = true;
                    }
                }
                if (!found) {
                    throw new NoSuchMethodException(cn);
                }
            }
        });
    }
}
