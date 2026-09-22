package com.sslkit.native_layer;

import android.content.Context;
import android.os.Build;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;
import com.sslkit.core.HookLogger;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * L2 · Native hook 安装器。
 *
 * ★ 关键坑（已实证）：
 *   LSPosed 的模块 ClassLoader 是 LspModuleClassLoader，它从 APK **动态加载 dex**，
 *   其 nativeLibraryDirectories 指向的是 `base.apk!/lib/arm64-v8a`（zip 内部路径），
 *   而 Android 的 `System.loadLibrary` **不支持 zip 内路径** →
 *   必然抛 `UnsatisfiedLinkError: couldn't find "libsslkit.so"`。
 *
 * 解法：自己从 APK 里把 .so 解压到私有目录，然后 `System.load(绝对路径)`。
 *   ① 优先用 ApplicationInfo.nativeLibraryDir（如果被安装时解压过）
 *   ② 回退：用 ZipFile 读 base.apk 的 lib/arm64-v8a/libsslkit.so → 写私有目录 → load
 */
public class NativeHookInstaller extends BaseHook {

    public static final String LIB_NAME = "libsslkit.so";
    private static final String ABI = "arm64-v8a";

    private static boolean sLoaded = false;
    private static boolean sLoadTried = false;
    private static String sLoadedPath = null;

    public NativeHookInstaller(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    public static native int nativeInstall();
    public static native int nativeRescan();
    public static native String nativeStats();
    public static native String nativeVersion();

    @Override
    public void install() {
        // 触发系统 SSL 库加载（让 native 侧扫得到）
        try {
            Class.forName("com.android.org.conscrypt.OpenSSLSocketFactoryImpl", false, cl);
        } catch (Throwable ignored) {
        }

        if (!loadLibrary()) {
            HookLogger.skip("L2.Native", "so-load-failed");
            return;
        }
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

        tryHook("L2.Native.version", new HookAction() {
            @Override
            public void run() throws Throwable {
                module.info("[SSLKit] " + nativeVersion());
            }
        });
    }

    // =====================================================================
    //  加载 libsslkit.so（多路兜底）
    // =====================================================================
    private synchronized boolean loadLibrary() {
        if (sLoaded) {
            return true;
        }
        if (sLoadTried) {
            return false;
        }
        sLoadTried = true;

        // ---- 路径 1：标准 loadLibrary（普通 App 可用） ----
        try {
            System.loadLibrary("sslkit");
            sLoaded = true;
            sLoadedPath = "(system)";
            module.info("[SSLKit] libsslkit.so loaded via loadLibrary");
            return true;
        } catch (Throwable t) {
            module.info("[SSLKit] loadLibrary failed, trying manual extract...");
        }

        // ---- 路径 2：从 App 的 nativeLibraryDir 找 ----
        String p;
        p = tryNativeLibDir();
        if (p != null && doLoad(p)) {
            return true;
        }

        // ---- 路径 3：从模块 APK 里解压出来 → 私有目录 ----
        p = tryExtractFromModuleApk();
        if (p != null && doLoad(p)) {
            return true;
        }

        // ---- 路径 4：从目标 App 的 APK 里找（极少见） ----
        p = tryExtractFromHostApk();
        if (p != null && doLoad(p)) {
            return true;
        }

        module.logError("[SSLKit] all load paths failed", new RuntimeException("cannot load " + LIB_NAME));
        return false;
    }

    private boolean doLoad(String path) {
        try {
            System.load(path);
            sLoaded = true;
            sLoadedPath = path;
            module.info("[SSLKit] libsslkit.so loaded from " + path);
            return true;
        } catch (Throwable t) {
            module.logError("[SSLKit] System.load(" + path + ") failed", t);
            return false;
        }
    }

    /** 路径 2：ApplicationInfo.nativeLibraryDir */
    private String tryNativeLibDir() {
        try {
            // 从当前进程拿 ApplicationInfo（模块自己跑在目标进程里）
            Class<?> atClass = Class.forName("android.app.ActivityThread", false, cl);
            Object at = atClass.getMethod("currentActivityThread").invoke(null);
            Object app = atClass.getMethod("getApplication").invoke(at);
            if (app == null) {
                return null;
            }
            Context ctx = (Context) app;
            String dir = ctx.getApplicationInfo().nativeLibraryDir;
            if (dir == null) {
                return null;
            }
            File f = new File(dir, LIB_NAME);
            if (f.exists()) {
                return f.getAbsolutePath();
            }
            // 有些设备会把模块的 so 放在这里
            File[] list = new File(dir).listFiles();
            if (list != null) {
                for (File x : list) {
                    if (x.getName().contains("sslkit")) {
                        return x.getAbsolutePath();
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    /** 路径 3：从模块自己的 APK 解压 */
    private String tryExtractFromModuleApk() {
        try {
            // 模块 APK 路径：从 ClassLoader 里找
            String apk = findModuleApkPath();
            if (apk == null) {
                module.info("[SSLKit] module apk path not found");
                return null;
            }
            return extractSoFromApk(apk);
        } catch (Throwable t) {
            module.logError("[SSLKit] extract from module apk failed", t);
        }
        return null;
    }

    /** 从 ClassLoader 的 toString 里抠出 base.apk 路径（LspModuleClassLoader[module=/data/app/.../base.apk]） */
    private String findModuleApkPath() {
        try {
            String s = cl.toString();
            int i = s.indexOf("module=");
            if (i >= 0) {
                int j = s.indexOf(',', i);
                String p = (j > 0) ? s.substring(i + 7, j) : s.substring(i + 7);
                p = p.trim();
                // 去掉可能的 ]
                int k = p.indexOf(']');
                if (k > 0) {
                    p = p.substring(0, k);
                }
                if (new File(p).exists()) {
                    return p;
                }
            }
        } catch (Throwable ignored) {
        }

        // 兜底：扫 /data/app 找 com.sslkit
        try {
            File base = new File("/data/app");
            File[] dirs = base.listFiles();
            if (dirs != null) {
                for (File d : dirs) {
                    File[] subs = d.listFiles();
                    if (subs == null) {
                        continue;
                    }
                    for (File s : subs) {
                        if (s.getName().startsWith("com.sslkit") && s.isDirectory()) {
                            File apk = new File(s, "base.apk");
                            if (!apk.exists()) {
                                File[] fs = s.listFiles();
                                if (fs != null) {
                                    for (File f : fs) {
                                        if (f.getName().endsWith(".apk")) {
                                            return f.getAbsolutePath();
                                        }
                                    }
                                }
                            } else {
                                return apk.getAbsolutePath();
                            }
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    /** 从 APK zip 里读 lib/<abi>/libsslkit.so 写到私有目录 */
    private String extractSoFromApk(String apkPath) {
        ZipFile zf = null;
        InputStream in = null;
        FileOutputStream out = null;
        try {
            File cacheDir = getCacheDir();
            if (cacheDir == null) {
                return null;
            }
            File target = new File(cacheDir, LIB_NAME);
            if (target.exists() && target.length() > 0) {
                return target.getAbsolutePath();
            }

            zf = new ZipFile(apkPath);
            ZipEntry e = zf.getEntry("lib/" + ABI + "/" + LIB_NAME);
            if (e == null) {
                e = zf.getEntry("lib/" + ABI + "/sslkit.so");
            }
            if (e == null) {
                module.info("[SSLKit] " + LIB_NAME + " not in apk lib/" + ABI);
                return null;
            }
            in = zf.getInputStream(e);
            out = new FileOutputStream(target);
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            out.flush();
            out.close();
            out = null;
            in.close();
            in = null;
            zf.close();
            zf = null;

            target.setReadable(true, false);
            target.setExecutable(true, false);
            module.info("[SSLKit] extracted so -> " + target.getAbsolutePath()
                    + " (" + target.length() + " bytes)");
            return target.getAbsolutePath();
        } catch (Throwable t) {
            module.logError("[SSLKit] extractSoFromApk failed", t);
        } finally {
            try {
                if (in != null) in.close();
            } catch (Throwable ignored) {
            }
            try {
                if (out != null) out.close();
            } catch (Throwable ignored) {
            }
            try {
                if (zf != null) zf.close();
            } catch (Throwable ignored) {
            }
        }
        return null;
    }

    /** 路径 4：从宿主 App 的 APK 里找（几乎用不到） */
    private String tryExtractFromHostApk() {
        return null;
    }

    /** 拿一个可写目录（优先 App 私有 cache，其次 /data/local/tmp） */
    private File getCacheDir() {
        // 1) 目标 App 的 cache
        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread", false, cl);
            Object at = atClass.getMethod("currentActivityThread").invoke(null);
            Object app = atClass.getMethod("getApplication").invoke(at);
            if (app instanceof Context) {
                File d = ((Context) app).getCacheDir();
                if (d != null && (d.exists() || d.mkdirs())) {
                    return d;
                }
            }
        } catch (Throwable ignored) {
        }
        // 2) 回退 /data/local/tmp（root 设备可写）
        File f = new File("/data/local/tmp/sslkit");
        if (f.exists() || f.mkdirs()) {
            return f;
        }
        return null;
    }

    // =====================================================================
    //  对外查询
    // =====================================================================

    public static boolean isLoaded() {
        return sLoaded;
    }

    public static String loadedPath() {
        return sLoadedPath;
    }

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
