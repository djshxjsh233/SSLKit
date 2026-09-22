package com.sslkit.cronet;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import io.github.libxposed.api.XposedInterface;

/**
 * ★ Cronet 专杀（Java 侧）—— 字节 / Google 系的核心命门。
 *
 * 实证（番茄小说 7.3.9.65 / libsscronet.so）：
 *
 *   com.ttnet.org.chromium.net.AndroidCertVerifyResult
 *     public AndroidCertVerifyResult(int status)                          ← a=status, b 未赋值=false
 *     public AndroidCertVerifyResult(boolean knownRoot, List<X509Certificate> chain)  ← ★ a=0, b=knownRoot
 *     public int getStatus()              返回 a   (0 = CERTIFICATE_OK)
 *     public boolean isIssuedByKnownRoot() 返回 b   ★★★ 命门
 *
 *   → 装了用户 CA 后 isIssuedByKnownRoot=false → Cronet 判 ERR_CERT_AUTHORITY_INVALID → abort
 *   → 必须用【二参构造】才能同时把 a=0 和 b=true
 *
 * 同时覆盖：
 *   com.ttnet.org.chromium.net.X509Util（如果存在）
 *   org.chromium.net.*（Google 官方 cronet）
 */
public class CronetCertResultHook extends BaseHook {

    /** Cronet 各家的 AndroidCertVerifyResult 类名 */
    private static final String[] CERT_RESULT_CLASSES = {
            "com.ttnet.org.chromium.net.AndroidCertVerifyResult",
            "org.chromium.net.AndroidCertVerifyResult",
            "com.google.android.gms.net.AndroidCertVerifyResult"
    };

    /** Cronet 各家的 CertVerifyStatusAndroid 常量类 */
    private static final String[] CERT_STATUS_CLASSES = {
            "com.ttnet.org.chromium.net.CertVerifyStatusAndroid",
            "org.chromium.net.CertVerifyStatusAndroid"
    };

    /** Cronet X509Util 候选（部分版本有 Java 侧 verifyKeyChain） */
    private static final String[] X509UTIL_CLASSES = {
            "com.ttnet.org.chromium.net.X509Util",
            "org.chromium.net.X509Util"
    };

    public CronetCertResultHook(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    @Override
    public void install() {
        int hit = 0;
        for (final String cn : CERT_RESULT_CLASSES) {
            if (classExists(cn)) {
                hookCertResult(cn);
                hit++;
            }
        }
        for (final String cn : X509UTIL_CLASSES) {
            if (classExists(cn)) {
                hookX509Util(cn);
                hit++;
            }
        }
        if (hit == 0) {
            com.sslkit.core.HookLogger.skip("Cronet.Java", "no-cronet-class");
        } else {
            com.sslkit.core.HookLogger.ok("Cronet.Java(" + hit + ")");
        }
    }

    // ---------------------------------------------------------------------
    //  AndroidCertVerifyResult
    // ---------------------------------------------------------------------
    private void hookCertResult(final String cn) {
        // 1) getStatus() → 0 (CERTIFICATE_OK)
        tryHook(cn + ".getStatus", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                Method m = c.getDeclaredMethod("getStatus");
                hook(m, new XposedInterface.Hooker() {
                    @Override
                    public Object intercept(XposedInterface.Chain chain) throws Throwable {
                        return Integer.valueOf(0);
                    }
                });
            }
        });

        // 2) isIssuedByKnownRoot() → true  ★★★
        tryHook(cn + ".isIssuedByKnownRoot", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                Method m = c.getDeclaredMethod("isIssuedByKnownRoot");
                hook(m, new XposedInterface.Hooker() {
                    @Override
                    public Object intercept(XposedInterface.Chain chain) throws Throwable {
                        return Boolean.TRUE;
                    }
                });
            }
        });

        // 3) getCertificateChainEncoded() → 原样放行（链要真，不能造假）
        tryHook(cn + ".getCertificateChainEncoded", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                Method m = c.getDeclaredMethod("getCertificateChainEncoded");
                hook(m, new XposedInterface.Hooker() {
                    @Override
                    public Object intercept(XposedInterface.Chain chain) throws Throwable {
                        return chain.proceed();
                    }
                });
            }
        });

        // 4) ★ 构造器：强制 isIssuedByKnownRoot=true
        tryHook(cn + ".<init>", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                int n = 0;
                for (Constructor<?> ctor : c.getDeclaredConstructors()) {
                    Class<?>[] pts = ctor.getParameterTypes();
                    // 二参构造 (boolean, List)
                    if (pts.length == 2 && pts[0] == boolean.class
                            && List.class.isAssignableFrom(pts[1])) {
                        hook(ctor, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                Object[] a = chain.getArgs().toArray();
                                a[0] = Boolean.TRUE;   // ★ 强制 knownRoot=true
                                return chain.proceed(a);
                            }
                        });
                        n++;
                    }
                    // 一参构造 (int status) —— 让它走二参逻辑（用 set 字段的方式不好，
                    // 这里改成：proceed 之后反射把 b 字段置 true）
                    else if (pts.length == 1 && pts[0] == int.class) {
                        hook(ctor, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                Object[] a = chain.getArgs().toArray();
                                a[0] = Integer.valueOf(0);   // status = CERTIFICATE_OK
                                Object r = chain.proceed(a);
                                forceKnownRoot(chain.getThisObject());
                                return r;
                            }
                        });
                        n++;
                    }
                }
                if (n == 0) {
                    throw new NoSuchMethodException(cn + ".<init>");
                }
            }
        });
    }

    /** 反射把 b 字段（isIssuedByKnownRoot 的存储位）置 true */
    private void forceKnownRoot(Object obj) {
        if (obj == null) {
            return;
        }
        try {
            Class<?> c = obj.getClass();
            // 找所有 boolean 字段（b 就是它）
            for (java.lang.reflect.Field f : c.getDeclaredFields()) {
                if (f.getType() == boolean.class) {
                    f.setAccessible(true);
                    f.setBoolean(obj, true);
                }
            }
        } catch (Throwable ignored) {
        }
    }

    // ---------------------------------------------------------------------
    //  X509Util（部分版本有 Java 侧校验）
    // ---------------------------------------------------------------------
    private void hookX509Util(final String cn) {
        String[] methodNames = {
                "verifyKeyChain", "verifyCertificateChain",
                "checkServerTrusted", "verifyChain"
        };
        tryHook(cn + ".verify*", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                int n = 0;
                for (Method m : c.getDeclaredMethods()) {
                    String mn = m.getName();
                    boolean match = false;
                    for (String t : methodNames) {
                        if (mn.equals(t) || mn.contains("verifyKeyChain")
                                || mn.contains("verifyCertificateChain")) {
                            match = true;
                            break;
                        }
                    }
                    if (!match) {
                        continue;
                    }
                    final Class<?> rt = m.getReturnType();
                    hook(m, new XposedInterface.Hooker() {
                        @Override
                        public Object intercept(XposedInterface.Chain chain) throws Throwable {
                            // 返回 AndroidCertVerifyResult(0) 或等价物
                            return makeOkResult(rt);
                        }
                    });
                    n++;
                }
                if (n == 0) {
                    throw new NoSuchMethodException(cn);
                }
            }
        });
    }

    /** 尽力构造一个 "OK" 的结果对象 */
    private Object makeOkResult(Class<?> rt) {
        try {
            if (rt == void.class) {
                return null;
            }
            if (rt == boolean.class || rt == Boolean.class) {
                return Boolean.TRUE;
            }
            if (rt == int.class || rt == Integer.class) {
                return Integer.valueOf(0);
            }
            // AndroidCertVerifyResult(int)
            for (Constructor<?> ctor : rt.getDeclaredConstructors()) {
                Class<?>[] pts = ctor.getParameterTypes();
                if (pts.length == 1 && pts[0] == int.class) {
                    ctor.setAccessible(true);
                    return ctor.newInstance(0);
                }
            }
            // 二参构造
            for (Constructor<?> ctor : rt.getDeclaredConstructors()) {
                Class<?>[] pts = ctor.getParameterTypes();
                if (pts.length == 2 && pts[0] == boolean.class
                        && List.class.isAssignableFrom(pts[1])) {
                    ctor.setAccessible(true);
                    return ctor.newInstance(Boolean.TRUE, new ArrayList<Object>());
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }
}
