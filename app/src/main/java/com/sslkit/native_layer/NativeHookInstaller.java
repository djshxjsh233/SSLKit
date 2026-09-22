package com.sslkit.native_layer;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.ParcelFileDescriptor;

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
 * ★ 关键坑（已实证 logcat）：
 *   LSPosed 的模块 ClassLoader = LspModuleClassLoader，从 APK **动态加载 dex**，
 *   nativeLibraryDirectories 指向 `base.apk!/lib/arm64-v8a`（zip 内部路径），
 *   而 Android 的 `System.loadLibrary` **不支持 zip 内路径** →
 *   必然抛 UnsatisfiedLinkError: couldn't find "libsslkit.so"。
 *
 * ★ 正确解法（5 路兜底）：
 *   1) System.loadLibrary —— 普通 App 场景
 *   2) ApplicationInfo.nativeLibraryDir —— 安装时解压过的情况
 *   3) ★ module.getModuleApplicationInfo().sourceDir —— LSPosed 官方 API，最可靠
 *   4) ClassLoader.nativeLibraryDirectories 反推 apk 路径
 *   5) /data/app 扫目录
 *   拿到 apk 后：ZipFile 读 lib/arm64-v8a/libsslkit.so → 写私有目录 → System.load
 */
public class NativeHookInstaller extends BaseHook {

    public static final String LIB_NAME = "libsslkit.so";
    private static final String ABI = "arm64-v8a";

    private static boolean sLoaded = false;
    private static boolean sLoadTried = false;
    private static String sLoadedPath = null;
    /** 解压出来的 so 路径，供子进程/后续复用 */
    public static String SO_PATH = null;

    public NativeHookInstaller(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    public static native int nativeInstall();
    public static native int nativeRescan();
    public static native String nativeStats();
    public static native String nativeVersion();

    @Override
    public void install() {
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
    //  加载 libsslkit.so
    // =====================================================================
    private synchronized boolean loadLibrary() {
        if (sLoaded) {
            return true;
        }
        if (sLoadTried) {
            return false;
        }
        sLoadTried = true;

        // ---- 路 1：标准 loadLibrary ----
        try {
            System.loadLibrary("sslkit");
            sLoaded = true;
            sLoadedPath = "(system)";
            module.info("[SSLKit] libsslkit.so loaded via loadLibrary");
            return true;
        } catch (Throwable t) {
            module.info("[SSLKit] loadLibrary failed (" + t.getClass().getSimpleName() + "), trying manual extract");
        }

        // ---- 路 2：nativeLibraryDir ----
        String p = tryNativeLibDir();
        if (p != null && doLoad(p)) {
            return true;
        }

        // ---- 路 3：★ LSPosed 官方 API（最可靠） ----
        String apk = tryModuleApkFromFramework();
        if (apk == null) {
            // ---- 路 4：ClassLoader nativeLibraryDirectories 反推 ----
            apk = tryApkFromNativeLibDirs();
        }
        if (apk == null) {
            // ---- 路 5：扫 /data/app ----
            apk = scanDataApp();
        }

        if (apk != null) {
            module.info("[SSLKit] module apk resolved: " + apk);
            String so = extractSoFromApk(apk);
            if (so != null && doLoad(so)) {
                return true;
            }
        } else {
            module.info("[SSLKit] cannot resolve module apk path");
        }

        module.logError("[SSLKit] all load paths failed", new RuntimeException("cannot load " + LIB_NAME));
        return false;
    }

    private boolean doLoad(String path) {
        try {
            System.load(path);
            sLoaded = true;
            sLoadedPath = path;
            SO_PATH = path;
            module.info("[SSLKit] libsslkit.so loaded from " + path);
            return true;
        } catch (Throwable t) {
            module.logError("[SSLKit] System.load(" + path + ") failed", t);
            return false;
        }
    }

    // ---------------------------------------------------------------------
    //  路 2
    // ---------------------------------------------------------------------
    private String tryNativeLibDir() {
        try {
            String dir = null;
            // 优先用框架给的模块 ApplicationInfo
            try {
                ApplicationInfo ai = module.getModuleApplicationInfo();
                if (ai != null) {
                    dir = ai.nativeLibraryDir;
                }
            } catch (Throwable ignored) {
            }
            if (dir == null) {
                Context ctx = getHostContext();
                if (ctx != null) {
                    dir = ctx.getApplicationInfo().nativeLibraryDir;
                }
            }
            if (dir == null) {
                return null;
            }
            File f = new File(dir, LIB_NAME);
            if (f.exists()) {
                return f.getAbsolutePath();
            }
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

    // ---------------------------------------------------------------------
    //  路 3：★ LSPosed 官方 API
    // ---------------------------------------------------------------------
    private String tryModuleApkFromFramework() {
        try {
            ApplicationInfo ai = module.getModuleApplicationInfo();
            if (ai == null) {
                module.info("[SSLKit] getModuleApplicationInfo() = null");
                return null;
            }
            String p = ai.sourceDir;
            if (p != null && new File(p).exists()) {
                module.info("[SSLKit] module apk (framework API): " + p);
                return p;
            }
            String p2 = ai.publicSourceDir;
            if (p2 != null && new File(p2).exists()) {
                return p2;
            }
        } catch (Throwable t) {
            module.info("[SSLKit] getModuleApplicationInfo err: " + t);
        }
        return null;
    }

    // ---------------------------------------------------------------------
    //  路 4：ClassLoader nativeLibraryDirectories 反推
    // ---------------------------------------------------------------------
    private String tryApkFromNativeLibDirs() {
        try {
            Object pathList = null;
            Class<?> cur = cl.getClass();
            while (cur != null && cur != Object.class && pathList == null) {
                for (java.lang.reflect.Field f : cur.getDeclaredFields()) {
                    String n = f.getName().toLowerCase();
                    if (n.contains("pathlist")) {
                        f.setAccessible(true);
                        try {
                            pathList = f.get(cl);
                            if (pathList != null) {
                                break;
                            }
                        } catch (Throwable ignored) {
                        }
                    }
                }
                cur = cur.getSuperclass();
            }
            if (pathList == null) {
                return null;
            }
            Object libDirs = null;
            for (java.lang.reflect.Field f : pathList.getClass().getDeclaredFields()) {
                if (f.getName().toLowerCase().contains("nativelibrarydirectories")) {
                    f.setAccessible(true);
                    libDirs = f.get(pathList);
                    break;
                }
            }
            if (libDirs instanceof Object[]) {
                for (Object o : (Object[]) libDirs) {
                    String s = String.valueOf(o);
                    int idx = s.indexOf(".apk!");
                    if (idx > 0) {
                        String apk = s.substring(0, idx + 4);
                        if (new File(apk).exists()) {
                            module.info("[SSLKit] module apk (nativeLibDirs): " + apk);
                            return apk;
                        }
                    }
                }
            }
            // 也扫 dexElements 的 dexFile 路径
            Object dexEls = null;
            for (java.lang.reflect.Field f : pathList.getClass().getDeclaredFields()) {
                if (f.getName().toLowerCase().contains("dexelements")) {
                    f.setAccessible(true);
                    dexEls = f.get(pathList);
                    break;
                }
            }
            if (dexEls instanceof Object[]) {
                for (Object el : (Object[]) dexEls) {
                    if (el == null) {
                        continue;
                    }
                    String s = String.valueOf(el);
                    int idx = s.indexOf(".apk");
                    if (idx > 0) {
                        String apk = s.substring(0, idx + 4);
                        if (new File(apk).exists()) {
                            module.info("[SSLKit] module apk (dexElements): " + apk);
                            return apk;
                        }
                    }
                }
            }
        } catch (Throwable t) {
            module.info("[SSLKit] tryApkFromNativeLibDirs err: " + t);
        }
        return null;
    }

    // ---------------------------------------------------------------------
    //  路 5：扫 /data/app
    // ---------------------------------------------------------------------
    private String scanDataApp() {
        for (String root : new String[]{"/data/app", "/data/app-private", "/mnt/expand"}) {
            try {
                File base = new File(root);
                File[] dirs = base.listFiles();
                if (dirs == null) {
                    continue;
                }
                for (File d : dirs) {
                    File[] subs = d.listFiles();
                    if (subs == null) {
                        continue;
                    }
                    for (File s : subs) {
                        if (!s.isDirectory() || !s.getName().startsWith("com.sslkit")) {
                            continue;
                        }
                        File[] fs = s.listFiles();
                        if (fs == null) {
                            continue;
                        }
                        for (File f : fs) {
                            if (f.getName().endsWith(".apk") && f.isFile()) {
                                module.info("[SSLKit] module apk (scan " + root + "): " + f.getAbsolutePath());
                                return f.getAbsolutePath();
                            }
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
        }
        return null;
    }

    // ---------------------------------------------------------------------
    //  从 APK 解压 so
    // ---------------------------------------------------------------------
    private String extractSoFromApk(String apkPath) {
        ZipFile zf = null;
        InputStream in = null;
        FileOutputStream out = null;
        try {
            File cacheDir = getWritableDir();
            if (cacheDir == null) {
                module.info("[SSLKit] no writable dir for so");
                return null;
            }
            File target = new File(cacheDir, LIB_NAME);
            if (target.exists() && target.length() > 0) {
                target.setReadable(true, false);
                target.setExecutable(true, false);
                return target.getAbsolutePath();
            }

            zf = new ZipFile(apkPath);
            ZipEntry e = zf.getEntry("lib/" + ABI + "/" + LIB_NAME);
            if (e == null) {
                // 遍历找任意 abi
                java.util.Enumeration<? extends ZipEntry> en = zf.entries();
                while (en.hasMoreElements()) {
                    ZipEntry x = en.nextElement();
                    String n = x.getName();
                    if (n.startsWith("lib/") && n.endsWith("/" + LIB_NAME)) {
                        e = x;
                        break;
                    }
                }
            }
            if (e == null) {
                module.info("[SSLKit] " + LIB_NAME + " not found inside " + apkPath);
                return null;
            }

            in = zf.getInputStream(e);
            out = new FileOutputStream(target);
            byte[] buf = new byte[16384];
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
                    + " (" + target.length() + " bytes, entry=" + e.getName() + ")");
            return target.getAbsolutePath();
        } catch (Throwable t) {
            module.logError("[SSLKit] extractSoFromApk failed", t);
        } finally {
            closeQuietly(in);
            closeQuietly(out);
            closeQuietly(zf);
        }
        return null;
    }

    private static void closeQuietly(Object o) {
        try {
            if (o instanceof java.io.Closeable) {
                ((java.io.Closeable) o).close();
            }
        } catch (Throwable ignored) {
        }
    }

    /** 找一个可写目录 */
    private File getWritableDir() {
        // 1) /data/local/tmp/sslkit（root 设备最稳，且其它进程也能读到）
        File f = new File("/data/local/tmp/sslkit");
        if (f.exists() || f.mkdirs()) {
            if (f.canWrite()) {
                return f;
            }
        }
        // 2) 宿主 App 的 cache
        try {
            Context ctx = getHostContext();
            if (ctx != null) {
                File d = ctx.getCacheDir();
                if (d != null && (d.exists() || d.mkdirs())) {
                    return d;
                }
            }
        } catch (Throwable ignored) {
        }
        // 3) 模块自己的 cache（通过框架）
        try {
            String p = module.getRemotePreferences("x").toString();
        } catch (Throwable ignored) {
        }
        // 4) /data/local/tmp 根
        File t = new File("/data/local/tmp");
        if (t.canWrite()) {
            return t;
        }
        return null;
    }

    /** 拿宿主 App 的 Context */
    private Context getHostContext() {
        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread", false, cl);
            Object at = atClass.getMethod("currentActivityThread").invoke(null);
            Object app = atClass.getMethod("getApplication").invoke(at);
            if (app instanceof Context) {
                return (Context) app;
            }
        } catch (Throwable ignored) {
        }
        // 备选：ActivityThread.currentApplication()
        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread", false, cl);
            Object app = atClass.getMethod("currentApplication").invoke(null);
            if (app instanceof Context) {
                return (Context) app;
            }
        } catch (Throwable ignored) {
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
