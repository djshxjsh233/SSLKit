package com.sslkit.java_layer;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;
import com.sslkit.core.SSLFactory;

import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import io.github.libxposed.api.XposedInterface;

/**
 * L1 · SSLContext / TrustManagerFactory / HttpsURLConnection
 *
 * 覆盖：
 *  - SSLContext.init(KeyManager[], TrustManager[], SecureRandom)   → 塞 trustAll
 *  - TrustManagerFactory.getTrustManagers()                        → 返回 trustAll
 *  - HttpsURLConnection.{setDefaultHostnameVerifier, setSSLSocketFactory,
 *                         setHostnameVerifier, setDefaultSSLSocketFactory}
 *  - TrustManagerImpl / NetworkSecurityTrustManager 的校验方法
 *  - X509TrustManager 接口的 check* 方法（拦所有实现）
 */
public class SSLContextHook extends BaseHook {

    public SSLContextHook(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    @Override
    public void install() {
        hookSSLContextInit();
        hookTrustManagerFactory();
        hookHttpsURLConnection();
        hookTrustManagerImpls();
        hookX509TrustManagerInterface();
    }

    // ---------------------------------------------------------------------
    //  SSLContext.init
    // ---------------------------------------------------------------------
    private void hookSSLContextInit() {
        final String cn = "javax.net.ssl.SSLContext";
        if (!classExists(cn)) {
            return;
        }
        tryHook("SSLContext.init", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                Method m = c.getDeclaredMethod("init",
                        KeyManager[].class, TrustManager[].class, SecureRandom.class);
                hook(m, new XposedInterface.Hooker() {
                    @Override
                    public Object intercept(XposedInterface.Chain chain) throws Throwable {
                        List<Object> args = chain.getArgs();
                        Object[] a = args.toArray();
                        if (a.length >= 2) {
                            a[1] = SSLFactory.trustAllManagers();
                        }
                        return chain.proceed(a);
                    }
                });
            }
        });
    }

    // ---------------------------------------------------------------------
    //  TrustManagerFactory.getTrustManagers
    // ---------------------------------------------------------------------
    private void hookTrustManagerFactory() {
        final String cn = "javax.net.ssl.TrustManagerFactory";
        if (!classExists(cn)) {
            return;
        }
        tryHook("TrustManagerFactory.getTrustManagers", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                boolean found = false;
                for (Method m : c.getDeclaredMethods()) {
                    if (!m.getName().equals("getTrustManagers")) {
                        continue;
                    }
                    hook(m, new XposedInterface.Hooker() {
                        @Override
                        public Object intercept(XposedInterface.Chain chain) throws Throwable {
                            return SSLFactory.trustAllManagers();
                        }
                    });
                    found = true;
                }
                if (!found) {
                    throw new NoSuchMethodException("getTrustManagers");
                }
            }
        });
    }

    // ---------------------------------------------------------------------
    //  HttpsURLConnection
    // ---------------------------------------------------------------------
    private void hookHttpsURLConnection() {
        final String cn = "javax.net.ssl.HttpsURLConnection";
        if (!classExists(cn)) {
            return;
        }

        tryHook("HttpsURLConnection 实例 setter", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                int n = 0;
                for (Method m : c.getDeclaredMethods()) {
                    String mn = m.getName();
                    if (mn.equals("setSSLSocketFactory")) {
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                Object[] a = chain.getArgs().toArray();
                                a[0] = SSLFactory.getTrustAllSocketFactory();
                                return chain.proceed(a);
                            }
                        });
                        n++;
                    } else if (mn.equals("setHostnameVerifier")) {
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                Object[] a = chain.getArgs().toArray();
                                a[0] = SSLFactory.trustAllHostnameVerifier();
                                return chain.proceed(a);
                            }
                        });
                        n++;
                    }
                }
                if (n == 0) {
                    throw new NoSuchMethodException(cn);
                }
            }
        });

        tryHook("HttpsURLConnection 静态 setter", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                Method m1 = null, m2 = null;
                try {
                    m1 = c.getDeclaredMethod("setDefaultSSLSocketFactory", SSLSocketFactory.class);
                } catch (Throwable ignored) {
                }
                try {
                    m2 = c.getDeclaredMethod("setDefaultHostnameVerifier",
                            javax.net.ssl.HostnameVerifier.class);
                } catch (Throwable ignored) {
                }
                int n = 0;
                if (m1 != null) {
                    hook(m1, new XposedInterface.Hooker() {
                        @Override
                        public Object intercept(XposedInterface.Chain chain) throws Throwable {
                            Object[] a = chain.getArgs().toArray();
                            a[0] = SSLFactory.getTrustAllSocketFactory();
                            return chain.proceed(a);
                        }
                    });
                    n++;
                }
                if (m2 != null) {
                    hook(m2, new XposedInterface.Hooker() {
                        @Override
                        public Object intercept(XposedInterface.Chain chain) throws Throwable {
                            Object[] a = chain.getArgs().toArray();
                            a[0] = SSLFactory.trustAllHostnameVerifier();
                            return chain.proceed(a);
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

    // ---------------------------------------------------------------------
    //  TrustManagerImpl / NetworkSecurityTrustManager 的校验方法
    // ---------------------------------------------------------------------
    private void hookTrustManagerImpls() {
        String[] classNames = {
                "com.android.org.conscrypt.TrustManagerImpl",
                "org.conscrypt.TrustManagerImpl",
                "android.security.net.config.NetworkSecurityTrustManager"
        };
        for (final String cn : classNames) {
            if (!classExists(cn)) {
                continue;
            }
            tryHook(cn + ".check*", new HookAction() {
                @Override
                public void run() throws Throwable {
                    Class<?> c = Class.forName(cn, false, cl);
                    int n = 0;
                    for (Method m : c.getDeclaredMethods()) {
                        String mn = m.getName();
                        if (mn.startsWith("checkServerTrusted") || mn.startsWith("checkClientTrusted")
                                || mn.startsWith("checkTrusted") || mn.equals("verifyChain")
                                || mn.equals("checkPins")) {
                            final Method fm = m;
                            hook(m, new XposedInterface.Hooker() {
                                @Override
                                public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                    List<Object> args = chain.getArgs();
                                    Object first = args.isEmpty() ? null : args.get(0);
                                    return SSLFactory.bypassReturn(fm.getReturnType(), first);
                                }
                            });
                            n++;
                        }
                    }
                    if (n == 0) {
                        throw new NoSuchMethodException(cn);
                    }
                }
            });
        }
    }

    // ---------------------------------------------------------------------
    //  X509TrustManager 接口（拦所有实现）
    // ---------------------------------------------------------------------
    private void hookX509TrustManagerInterface() {
        String[] ifaces = {
                "javax.net.ssl.X509TrustManager",
                "javax.net.ssl.X509ExtendedTrustManager"
        };
        for (final String cn : ifaces) {
            if (!classExists(cn)) {
                continue;
            }
            tryHook(cn + ".check*", new HookAction() {
                @Override
                public void run() throws Throwable {
                    Class<?> c = Class.forName(cn, false, cl);
                    int n = 0;
                    for (Method m : c.getDeclaredMethods()) {
                        String mn = m.getName();
                        if (mn.startsWith("checkServerTrusted") || mn.startsWith("checkClientTrusted")) {
                            final Method fm = m;
                            hook(m, new XposedInterface.Hooker() {
                                @Override
                                public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                    List<Object> args = chain.getArgs();
                                    Object first = args.isEmpty() ? null : args.get(0);
                                    return SSLFactory.bypassReturn(fm.getReturnType(), first);
                                }
                            });
                            n++;
                        }
                    }
                    if (n == 0) {
                        throw new NoSuchMethodException(cn);
                    }
                }
            });
        }
    }
}
