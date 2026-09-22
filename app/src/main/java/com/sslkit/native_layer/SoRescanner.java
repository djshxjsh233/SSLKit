package com.sslkit.native_layer;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;

import java.lang.reflect.Method;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import io.github.libxposed.api.XposedInterface;

/**
 * L2 · so 动态加载重扫描。
 *
 * 问题：so 是运行时加载的。onPackageReady 时扫描只能扫到当时已加载的，
 * 像 libsscronet.so / libwechatnetwork.so 这类可能晚几百毫秒才 dlopen。
 *
 * 解法（双保险）：
 *   1. hook android_dlopen_ext / dlopen —— 新 so 加载后立刻重扫
 *   2. Java 侧轮询线程 —— 定期 nativeRescan，防 so 绕过 dlopen
 */
public class SoRescanner extends BaseHook {

    private static final AtomicBoolean sPolling = new AtomicBoolean(false);

    public SoRescanner(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    @Override
    public void install() {
        hookDlopen();
        startPolling();
    }

    /** 方案 1：hook native linker 的 dlopen 入口 */
    private void hookDlopen() {
        String[] targets = {
                "android_dlopen_ext",
                "dlopen",
                "__dl__Z9do_dlopenPKciPK17android_dlextinfoPKv"
        };
        // Java 层看不到 native dlopen，这里走 native hook 的 rescan
        // （native 侧 constructor 已自动 hook 一次，这里做补充调用）
        tryHook("L2.SoRescanner.dlopen(补)", new HookAction() {
            @Override
            public void run() throws Throwable {
                if (!NativeHookInstaller.isLoaded()) {
                    throw new IllegalStateException("native not loaded");
                }
                int n = NativeHookInstaller.rescan();
                module.info("[SSLKit] rescanner initial rescan: " + n);
            }
        });
    }

    /** 方案 2：Java 侧轮询（500ms 一次，跑 30 次 ≈ 15 秒） */
    private void startPolling() {
        if (!NativeHookInstaller.isLoaded()) {
            return;
        }
        if (!sPolling.compareAndSet(false, true)) {
            return;
        }
        tryHook("L2.SoRescanner.polling", new HookAction() {
            @Override
            public void run() throws Throwable {
                Thread t = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        int last = -1;
                        for (int i = 0; i < 40; i++) {
                            try {
                                Thread.sleep(500);
                            } catch (InterruptedException e) {
                                return;
                            }
                            try {
                                int n = NativeHookInstaller.rescan();
                                if (n != last) {
                                    module.info("[SSLKit] rescan #" + i + " -> " + n + " symbols");
                                    last = n;
                                }
                            } catch (Throwable ignored) {
                            }
                        }
                        // 最后打印统计
                        try {
                            module.info("[SSLKit] native stats: " + NativeHookInstaller.stats());
                        } catch (Throwable ignored) {
                        }
                    }
                }, "SSLKit-Rescanner");
                t.setDaemon(true);
                t.start();
                module.info("[SSLKit] so rescanner started (40 x 500ms)");
            }
        });
    }
}
