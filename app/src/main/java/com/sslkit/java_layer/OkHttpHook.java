package com.sslkit.java_layer;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;
import com.sslkit.core.SSLFactory;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import io.github.libxposed.api.XposedInterface;

/**
 * L1 · OkHttp 全版本。
 *
 * 覆盖：
 *   okhttp3.CertificatePinner.check(String, List)
 *   okhttp3.CertificatePinner.check(String, Function0)     (kotlin lambda 版)
 *   okhttp3.CertificatePinner.check$okhttp
 *   okhttp3.CertificatePinner.findMatchingPins(String)
 *   com.squareup.okhttp.CertificatePinner.check           (okhttp 2.x)
 *
 * ★ 混淆版定位（吸收 JustTrustMePro 思路并强化）：
 *   OkHttp 混淆后类名全没了，但字段名往往保留（noNewStreams / address / route）。
 *   通过 "有 boolean noNewStreams 字段" 认 RealConnection，
 *   再顺着字段类型链找到 Address，把它的 certificatePinner 换成空的。
 */
public class OkHttpHook extends BaseHook {

    public OkHttpHook(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    @Override
    public void install() {
        hookOkHttp3();
        hookOkHttp2();
        hookOkHttp3Lambda();
        if (com.sslkit.Config.OKHTTP_OBFUSCATED) {
            hookObfuscatedByStack();
        }
    }

    // ---------------------------------------------------------------------
    //  OkHttp 3
    // ---------------------------------------------------------------------
    private void hookOkHttp3() {
        final String cn = "okhttp3.CertificatePinner";
        if (!classExists(cn)) {
            com.sslkit.core.HookLogger.skip(cn, "okhttp3-not-found");
            return;
        }

        // check(String, List) → 直接返回
        tryHook("okhttp3.CertificatePinner.check(String,List)", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                Method m = null;
                for (Method mm : c.getDeclaredMethods()) {
                    if (mm.getName().equals("check")) {
                        Class<?>[] pts = mm.getParameterTypes();
                        if (pts.length == 2 && pts[0] == String.class) {
                            m = mm;
                            break;
                        }
                    }
                }
                if (m == null) {
                    throw new NoSuchMethodException("check(String,List)");
                }
                hook(m, new XposedInterface.Hooker() {
                    @Override
                    public Object intercept(XposedInterface.Chain chain) throws Throwable {
                        return null;   // check 返回 void
                    }
                });
            }
        });

        // check$okhttp(String, Function0) → 直接返回
        tryHook("okhttp3.CertificatePinner.check$okhttp", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                Method m = null;
                for (Method mm : c.getDeclaredMethods()) {
                    if (mm.getName().startsWith("check$okhttp")) {
                        m = mm;
                        break;
                    }
                }
                if (m == null) {
                    throw new NoSuchMethodException("check$okhttp");
                }
                hook(m, new XposedInterface.Hooker() {
                    @Override
                    public Object intercept(XposedInterface.Chain chain) throws Throwable {
                        return null;
                    }
                });
            }
        });

        // findMatchingPins(String) → 返回空 List（让 check 找不到 pin）
        tryHook("okhttp3.CertificatePinner.findMatchingPins", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                Method m = null;
                for (Method mm : c.getDeclaredMethods()) {
                    if (mm.getName().equals("findMatchingPins")) {
                        m = mm;
                        break;
                    }
                }
                if (m == null) {
                    throw new NoSuchMethodException("findMatchingPins");
                }
                final Class<?> rt = m.getReturnType();
                hook(m, new XposedInterface.Hooker() {
                    @Override
                    public Object intercept(XposedInterface.Chain chain) throws Throwable {
                        if (List.class.isAssignableFrom(rt)) {
                            return new ArrayList<Object>();
                        }
                        return SSLFactory.bypassReturn(rt, null);
                    }
                });
            }
        });
    }

    // ---------------------------------------------------------------------
    //  OkHttp 2
    // ---------------------------------------------------------------------
    private void hookOkHttp2() {
        final String cn = "com.squareup.okhttp.CertificatePinner";
        if (!classExists(cn)) {
            com.sslkit.core.HookLogger.skip(cn, "okhttp2-not-found");
            return;
        }
        tryHook("okhttp2.CertificatePinner.check", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                for (Method m : c.getDeclaredMethods()) {
                    if (!m.getName().equals("check")) {
                        continue;
                    }
                    hook(m, new XposedInterface.Hooker() {
                        @Override
                        public Object intercept(XposedInterface.Chain chain) throws Throwable {
                            return null;
                        }
                    });
                }
            }
        });
    }

    // ---------------------------------------------------------------------
    //  OkHttp 3 Kotlin lambda 版
    // ---------------------------------------------------------------------
    private void hookOkHttp3Lambda() {
        final String cn = "okhttp3.CertificatePinner";
        if (!classExists(cn)) {
            return;
        }
        tryHook("okhttp3.CertificatePinner 全部方法兜底", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                int n = 0;
                for (Method m : c.getDeclaredMethods()) {
                    String mn = m.getName();
                    if (mn.equals("check") && !isHookedAlready(m)) {
                        final Class<?> rt = m.getReturnType();
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                return SSLFactory.bypassReturn(rt, null);
                            }
                        });
                        n++;
                    }
                }
                if (n == 0) {
                    throw new NoSuchMethodException("no extra check");
                }
            }
        });
    }

    private boolean isHookedAlready(Method m) {
        return false;   // 允许重复 hook，libxposed 内部会处理
    }

    // ---------------------------------------------------------------------
    //  ★ 混淆版：按字段特征定位 RealConnection → Route → Address → certificatePinner
    // ---------------------------------------------------------------------
    private void hookObfuscatedByStack() {
        tryHook("OkHttp 混淆版定位（hook OpenSSLSocketFactoryImpl.createSocket）", new HookAction() {
            @Override
            public void run() throws Throwable {
                String sslFactoryCn = "com.android.org.conscrypt.OpenSSLSocketFactoryImpl";
                if (!classExists(sslFactoryCn)) {
                    throw new ClassNotFoundException(sslFactoryCn);
                }
                Class<?> c = Class.forName(sslFactoryCn, false, cl);
                boolean installed = false;
                for (final Method m : c.getDeclaredMethods()) {
                    if (!m.getName().equals("createSocket")) {
                        continue;
                    }
                    hook(m, new XposedInterface.Hooker() {
                        @Override
                        public Object intercept(XposedInterface.Chain chain) throws Throwable {
                            try {
                                installByStack(Thread.currentThread().getStackTrace());
                            } catch (Throwable ignored) {
                            }
                            return chain.proceed();
                        }
                    });
                    installed = true;
                }
                if (!installed) {
                    throw new NoSuchMethodException("createSocket");
                }
            }
        });
    }

    private static final HashSet<String> TRIED = new HashSet<String>();

    private void installByStack(StackTraceElement[] stack) {
        if (stack == null) {
            return;
        }
        for (StackTraceElement e : stack) {
            String cn = e.getClassName();
            if (cn == null || TRIED.contains(cn)) {
                continue;
            }
            if (cn.startsWith("com.android.org.conscrypt") || cn.startsWith("java.")
                    || cn.startsWith("javax.") || cn.startsWith("com.sslkit.")) {
                continue;
            }
            TRIED.add(cn);
            try {
                Class<?> c = Class.forName(cn, false, cl);
                if (isRealConnection(c)) {
                    hookAddressFromRealConnection(c);
                    return;
                }
            } catch (Throwable ignored) {
            }
        }
    }

    /** RealConnection 特征：有 boolean noNewStreams 字段 */
    private boolean isRealConnection(Class<?> c) {
        try {
            for (Field f : c.getDeclaredFields()) {
                if (f.getType() == boolean.class && "noNewStreams".equals(f.getName())) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    /**
     * RealConnection → route 字段 → Route 类 → address 字段 → Address 类
     * → certificatePinner 字段 → hook Address 构造器，把 pinner 换掉
     */
    private void hookAddressFromRealConnection(Class<?> realConnection) {
        try {
            Class<?> routeClass = null;
            for (Field f : realConnection.getDeclaredFields()) {
                Class<?> ft = f.getType();
                for (Field f2 : ft.getDeclaredFields()) {
                    if ("address".equals(f2.getName())) {
                        routeClass = ft;
                        break;
                    }
                }
                if (routeClass != null) {
                    break;
                }
            }
            if (routeClass == null) {
                return;
            }

            Class<?> addressClass = null;
            for (Field f : routeClass.getDeclaredFields()) {
                if ("address".equals(f.getName())) {
                    addressClass = f.getType();
                    break;
                }
            }
            if (addressClass == null) {
                return;
            }

            // 找 certificatePinner 字段类型
            final Class<?> pinnerClass;
            Field pf = null;
            for (Field f : addressClass.getDeclaredFields()) {
                if ("certificatePinner".equals(f.getName())) {
                    pf = f;
                    break;
                }
            }
            if (pf == null) {
                return;
            }
            pinnerClass = pf.getType();

            // 找一个 "空 pinner" 实例（反射调 get() / DEFAULT）
            final Object emptyPinner = findEmptyPinner(pinnerClass);

            for (final java.lang.reflect.Constructor<?> ctor : addressClass.getDeclaredConstructors()) {
                try {
                    hook(ctor, new XposedInterface.Hooker() {
                        @Override
                        public Object intercept(XposedInterface.Chain chain) throws Throwable {
                            Object[] a = chain.getArgs().toArray();
                            for (int i = 0; i < a.length; i++) {
                                if (a[i] != null && a[i].getClass() == pinnerClass) {
                                    if (emptyPinner != null) {
                                        a[i] = emptyPinner;
                                    }
                                }
                            }
                            return chain.proceed(a);
                        }
                    });
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private Object findEmptyPinner(Class<?> pinnerClass) {
        // CertificatePinner.DEFAULT / get() / EMPTY
        String[] names = {"DEFAULT", "EMPTY", "NONE"};
        for (String n : names) {
            try {
                Field f = pinnerClass.getDeclaredField(n);
                f.setAccessible(true);
                Object v = f.get(null);
                if (v != null) {
                    return v;
                }
            } catch (Throwable ignored) {
            }
        }
        // 反射调静态 get()
        try {
            Method m = pinnerClass.getDeclaredMethod("get");
            m.setAccessible(true);
            return m.invoke(null);
        } catch (Throwable ignored) {
        }
        return null;
    }
}
