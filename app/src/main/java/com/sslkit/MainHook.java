package com.sslkit;

import android.util.Log;

import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface.ModuleLoadedParam;
import io.github.libxposed.api.XposedModuleInterface.PackageLoadedParam;
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam;

/**
 * SSLKit 入口（libxposed API 102）。
 *
 * 生命周期：
 *   onModuleLoaded  → 模块加载（记录进程名）
 *   onPackageLoaded → 目标 App 加载（★ 这里能拿包名）
 *   onPackageReady  → 目标 App 就绪（★ 这里 ClassLoader 齐全，做实际 hook）
 *
 * 设计原则：
 *   - 不针对任何单一 App，纯通用
 *   - 每层独立 try/catch，任何一层炸了不影响其它层
 *   - 所有 hook 前先查配置开关
 */
public class MainHook extends XposedModule {

    public static final String TAG = "SSLKit";
    public static final String VERSION = "1.0.0";

    private static MainHook sInstance;

    /** onPackageLoaded 缓存的包名（onPackageReady 拿不到，必须在这里存） */
    private String pendingPackageName;
    private boolean hooked;

    public MainHook() {
        super();
        sInstance = this;
    }

    public static MainHook get() {
        return sInstance;
    }

    @Override
    public void onModuleLoaded(ModuleLoadedParam param) {
        log(Log.INFO, TAG, "[SSLKit] v" + VERSION + " loaded in " + param.getProcessName()
                + " (systemServer=" + param.isSystemServer() + ")");
    }

    @Override
    public void onPackageLoaded(PackageLoadedParam param) {
        try {
            pendingPackageName = param.getPackageName();
            log(Log.INFO, TAG, "[SSLKit] onPackageLoaded: " + pendingPackageName
                    + " first=" + param.isFirstPackage());
        } catch (Throwable t) {
            logError("onPackageLoaded", t);
        }
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        try {
            if (hooked) {
                return;
            }
            hooked = true;

            ClassLoader cl = param.getClassLoader();
            String pkg = pendingPackageName != null ? pendingPackageName : "(unknown)";

            log(Log.INFO, TAG, "[SSLKit] onPackageReady: " + pkg);
            new HookOrchestrator(this, cl, pkg).run();
        } catch (Throwable t) {
            logError("onPackageReady fatal", t);
        }
    }

    // ---------------------------------------------------------------------
    //  日志
    // ---------------------------------------------------------------------

    public void info(String msg) {
        try {
            log(Log.INFO, TAG, msg);
        } catch (Throwable ignored) {
        }
        try {
            Log.i(TAG, msg);
        } catch (Throwable ignored) {
        }
    }

    public void logError(String msg, Throwable t) {
        try {
            log(Log.ERROR, TAG, msg, t);
        } catch (Throwable ignored) {
        }
        try {
            Log.e(TAG, msg, t);
        } catch (Throwable ignored) {
        }
    }
}
