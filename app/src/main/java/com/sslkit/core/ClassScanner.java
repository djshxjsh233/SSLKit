package com.sslkit.core;

import com.sslkit.Config;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import dalvik.system.DexFile;

/**
 * ★ 全量类扫描引擎 —— SSLKit 通用性的核心。
 *
 * JustTrustMePro 写好了 allClassNamesFromClassLoader 却只拿来猜 WebView 类名。
 * 这里把它真正落地：扫出全部类名 → 多轮过滤 → 找出所有可疑的证书校验类。
 *
 * 三轮过滤：
 *   轮1 字符串层：类名含关键词（Trust/Pin/Verify/Cert/Ssl/X509/Https...）
 *                 —— 不 loadClass，避免触发静态初始化
 *   轮2 类型层：loadClass 后检查是否实现 X509TrustManager / X509ExtendedTrustManager
 *   轮3 方法层：检查是否有 checkServerTrusted / verify / check / verifyChain 等
 *                 且参数含证书 / String host 特征
 */
public final class ClassScanner {

    public static class Hit {
        public final String className;
        public final Class<?> clazz;
        /** 命中原因，便于调试 */
        public final String reason;

        Hit(String className, Class<?> clazz, String reason) {
            this.className = className;
            this.clazz = clazz;
            this.reason = reason;
        }

        @Override
        public String toString() {
            return className + " (" + reason + ")";
        }
    }

    /**
     * 扫描并返回所有疑似证书校验类。
     */
    public static List<Hit> scan(ClassLoader cl) {
        List<Hit> out = new ArrayList<Hit>();
        if (cl == null) {
            return out;
        }

        Set<String> allNames = allClassNames(cl);
        if (allNames.isEmpty()) {
            return out;
        }

        // ---- 轮1：字符串过滤 ----
        List<String> candidates = new ArrayList<String>();
        for (String name : allNames) {
            if (name == null || name.isEmpty() || name.indexOf('$') >= 0) {
                continue;   // 跳过内部类，减少噪声
            }
            if (isExcluded(name)) {
                continue;
            }
            if (matchesKeyword(name)) {
                candidates.add(name);
            }
        }

        // ---- 轮2 + 轮3：加载并检查 ----
        for (String name : candidates) {
            Class<?> c;
            try {
                c = Class.forName(name, false, cl);   // false=不初始化
            } catch (Throwable t) {
                continue;
            }
            String reason = classify(c);
            if (reason != null) {
                out.add(new Hit(name, c, reason));
            }
        }
        return out;
    }

    /**
     * 判断一个类是不是"证书校验类"。
     *
     * @return 命中原因；不命中返回 null
     */
    private static String classify(Class<?> c) {
        try {
            // 轮2：TrustManager 实现
            if (X509TrustManager.class.isAssignableFrom(c)) {
                return "implements X509TrustManager";
            }
            if (X509ExtendedTrustManager.class.isAssignableFrom(c)) {
                return "implements X509ExtendedTrustManager";
            }

            // 轮3：方法特征
            boolean hasCheckServerTrusted = false;
            boolean hasVerify = false;
            boolean hasPinner = false;
            boolean hasCertParam = false;

            for (java.lang.reflect.Method m : c.getDeclaredMethods()) {
                String mn = m.getName();
                if (mn.equals("checkServerTrusted") || mn.equals("checkClientTrusted")
                        || mn.equals("checkTrusted") || mn.equals("verifyChain")) {
                    hasCheckServerTrusted = true;
                }
                if (mn.equals("verify") || mn.equals("verifyHostname")
                        || mn.equals("isSecure") || mn.equals("check")) {
                    hasVerify = true;
                }
                if (mn.equals("check") || mn.equals("check$okhttp")
                        || mn.equals("findMatchingPins") || mn.equals("checkPins")) {
                    hasPinner = true;
                }
                for (Class<?> p : m.getParameterTypes()) {
                    if (p == java.security.cert.X509Certificate.class
                            || p == java.security.cert.X509Certificate[].class
                            || p == java.security.cert.Certificate.class
                            || p == java.security.cert.Certificate[].class) {
                        hasCertParam = true;
                    }
                }
            }

            if (hasCheckServerTrusted && hasCertParam) {
                return "checkServerTrusted + cert param";
            }
            if (hasPinner && hasCertParam) {
                return "pinner-like";
            }
            if (hasPinner && !hasCertParam) {
                // 可能是 CertificatePinner（参数是 host + List<Pin>）
                String n = c.getSimpleName().toLowerCase();
                if (n.contains("pin")) {
                    return "CertificatePinner-like";
                }
            }
            if (hasVerify && hasCertParam) {
                return "verify + cert param";
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static boolean matchesKeyword(String name) {
        for (String kw : Config.SCAN_KEYWORDS) {
            if (name.regionMatches(true, 0, kw, 0, kw.length())) {
                return true;
            }
            int idx = indexOfIgnoreCase(name, kw);
            if (idx >= 0) {
                return true;
            }
        }
        return false;
    }

    private static int indexOfIgnoreCase(String s, String sub) {
        int max = s.length() - sub.length();
        for (int i = 0; i <= max; i++) {
            if (s.regionMatches(true, i, sub, 0, sub.length())) {
                return i;
            }
        }
        return -1;
    }

    private static boolean isExcluded(String name) {
        for (String p : Config.SCAN_EXCLUDE_PREFIX) {
            if (name.startsWith(p)) {
                return true;
            }
        }
        return false;
    }

    // =====================================================================
    //  从 ClassLoader 拿全部类名（传统做法 + 多路兜底）
    // =====================================================================

    public static Set<String> allClassNames(ClassLoader cl) {
        Set<String> names = new HashSet<String>();

        // 路1：BaseDexClassLoader → pathList → dexElements → DexFile.entries()
        try {
            if (collectByDexElements(cl, names)) {
                return names;
            }
        } catch (Throwable ignored) {
        }

        // 路2：经典 pathList 字段名
        String[] pathListFields = {"pathList", "dexPathList", "mPathList", "mDexPathList"};
        for (String fn : pathListFields) {
            try {
                Field f = findField(cl.getClass(), fn);
                if (f == null) {
                    continue;
                }
                f.setAccessible(true);
                Object pathList = f.get(cl);
                if (pathList == null) {
                    continue;
                }
                if (collectByDexElements(pathList, names)) {
                    return names;
                }
            } catch (Throwable ignored) {
            }
        }

        // 路3：递归父 ClassLoader（有些 App 用多层）
        try {
            ClassLoader parent = cl.getParent();
            if (parent != null && parent != cl) {
                names.addAll(allClassNames(parent));
            }
        } catch (Throwable ignored) {
        }

        return names;
    }

    private static Field findField(Class<?> c, String name) {
        Class<?> cur = c;
        while (cur != null && cur != Object.class) {
            try {
                return cur.getDeclaredField(name);
            } catch (Throwable ignored) {
            }
            cur = cur.getSuperclass();
        }
        return null;
    }

    /**
     * 从 pathList 对象里取 dexElements，再逐个 DexFile.entries()。
     */
    private static boolean collectByDexElements(Object pathList, Set<String> names) {
        try {
            Field ef = findField(pathList.getClass(), "dexElements");
            if (ef == null) {
                return false;
            }
            ef.setAccessible(true);
            Object arr = ef.get(pathList);
            if (!(arr instanceof Object[])) {
                return false;
            }
            boolean got = false;
            for (Object element : (Object[]) arr) {
                if (element == null) {
                    continue;
                }
                try {
                    Field df = findField(element.getClass(), "dexFile");
                    if (df == null) {
                        continue;
                    }
                    df.setAccessible(true);
                    Object dexFileObj = df.get(element);
                    if (!(dexFileObj instanceof DexFile)) {
                        continue;
                    }
                    DexFile dexFile = (DexFile) dexFileObj;
                    java.util.Enumeration<String> en = dexFile.entries();
                    while (en.hasMoreElements()) {
                        names.add(en.nextElement());
                    }
                    got = true;
                } catch (Throwable ignored) {
                }
            }
            return got;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private ClassScanner() {
    }
}
