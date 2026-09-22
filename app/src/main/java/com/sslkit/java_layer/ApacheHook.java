package com.sslkit.java_layer;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;
import com.sslkit.core.SSLFactory;

import java.lang.reflect.Method;
import java.util.List;

import io.github.libxposed.api.XposedInterface;

/**
 * L1 · Apache HttpClient + 第三方 http 库。
 *
 * 覆盖：
 *   org.apache.http.impl.client.DefaultHttpClient           构造器
 *   org.apache.http.conn.ssl.SSLSocketFactory.isSecure      → true
 *   ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier  → 放行
 *   org.xutils.http.RequestParams.setSslSocketFactory       → trustAll
 */
public class ApacheHook extends BaseHook {

    public ApacheHook(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    @Override
    public void install() {
        hookApacheHttpClient();
        hookApacheSSLSocketFactory();
        hookHttpclientAndroidLib();
        hookXUtils();
    }

    private void hookApacheHttpClient() {
        // 只 hook 类名，不引用编译期类型（避免 useLibrary org.apache.http.legacy 依赖）
        final String cn = "org.apache.http.impl.client.DefaultHttpClient";
        if (!classExists(cn)) {
            com.sslkit.core.HookLogger.skip(cn, "not-found");
            return;
        }
        tryHook(cn + ".<init>", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                int n = 0;
                for (java.lang.reflect.Constructor<?> ctor : c.getDeclaredConstructors()) {
                    hook(ctor, new XposedInterface.Hooker() {
                        @Override
                        public Object intercept(XposedInterface.Chain chain) throws Throwable {
                            Object r = chain.proceed();
                            try {
                                Object client = chain.getThisObject();
                                Object params = client.getClass()
                                        .getMethod("getParams").invoke(client);
                                params.getClass().getMethod("setParameter", String.class, Object.class)
                                        .invoke(params, "http.socket.factory",
                                                SSLFactory.getTrustAllSocketFactory());
                            } catch (Throwable ignored) {
                            }
                            return r;
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

    private void hookApacheSSLSocketFactory() {
        final String cn = "org.apache.http.conn.ssl.SSLSocketFactory";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".isSecure", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("isSecure")) {
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                return Boolean.TRUE;
                            }
                        });
                    }
                }
            }
        });
    }

    private void hookHttpclientAndroidLib() {
        final String cn = "ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".verify", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                int n = 0;
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("verify")) {
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                return null;
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

    private void hookXUtils() {
        final String cn = "org.xutils.http.RequestParams";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".setSslSocketFactory", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                for (Method m : c.getDeclaredMethods()) {
                    String mn = m.getName();
                    if (mn.equals("setSslSocketFactory")) {
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                Object[] a = chain.getArgs().toArray();
                                a[0] = SSLFactory.getTrustAllSocketFactory();
                                return chain.proceed(a);
                            }
                        });
                    } else if (mn.equals("setHostnameVerifier")) {
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                Object[] a = chain.getArgs().toArray();
                                a[0] = SSLFactory.trustAllHostnameVerifier();
                                return chain.proceed(a);
                            }
                        });
                    }
                }
            }
        });
    }
}
