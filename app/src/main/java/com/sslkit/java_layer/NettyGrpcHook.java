package com.sslkit.java_layer;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;
import com.sslkit.core.SSLFactory;

import java.lang.reflect.Method;
import java.util.List;

import io.github.libxposed.api.XposedInterface;

/**
 * L1 · Netty / gRPC / 其他自建 TLS 栈（★ JustTrustMePro 完全没有）。
 *
 * 覆盖：
 *   io.netty.handler.ssl.SslContextBuilder.trustManager(TrustManagerFactory/X509Certificate[])
 *   io.netty.handler.ssl.util.InsecureTrustManagerFactory
 *   io.netty.handler.ssl.SslContext.newClientContext(...) 的 trustManager 参数
 *   io.grpc.okhttp.OkHttpChannelBuilder.sslSocketFactory
 *   io.grpc.netty.NettyChannelBuilder.sslContext
 *
 * 这些库不走 Android 默认栈，普通 hook 打不到。
 */
public class NettyGrpcHook extends BaseHook {

    public NettyGrpcHook(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    @Override
    public void install() {
        hookNettySslContextBuilder();
        hookInsecureTrustManagerFactory();
        hookGrpcOkHttp();
        hookGrpcNetty();
        hookBouncyCastle();
    }

    // ---------------------------------------------------------------------
    //  Netty SslContextBuilder
    // ---------------------------------------------------------------------
    private void hookNettySslContextBuilder() {
        final String cn = "io.netty.handler.ssl.SslContextBuilder";
        if (!classExists(cn)) {
            com.sslkit.core.HookLogger.skip(cn, "netty-not-found");
            return;
        }
        tryHook(cn + ".trustManager(*)", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                int n = 0;
                for (Method m : c.getDeclaredMethods()) {
                    String mn = m.getName();
                    if (mn.equals("trustManager")) {
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                // 换成 InsecureTrustManagerFactory 的实例
                                Object insecure = makeInsecureTmf();
                                if (insecure != null) {
                                    Object[] a = chain.getArgs().toArray();
                                    if (a.length > 0) {
                                        a[0] = insecure;
                                        return chain.proceed(a);
                                    }
                                }
                                return chain.proceed();
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

        // InsecureTrustManagerFactory 的静态实例
        hookInsecureTmfSingleton();
    }

    private Object makeInsecureTmf() {
        try {
            Class<?> c = Class.forName("io.netty.handler.ssl.util.InsecureTrustManagerFactory",
                    false, cl);
            java.lang.reflect.Field f = c.getDeclaredField("INSTANCE");
            f.setAccessible(true);
            return f.get(null);
        } catch (Throwable ignored) {
        }
        return null;
    }

    private void hookInsecureTmfSingleton() {
        try {
            Class<?> c = Class.forName("io.netty.handler.ssl.util.InsecureTrustManagerFactory",
                    false, cl);
            for (Method m : c.getDeclaredMethods()) {
                if (m.getName().equals("newTrustManagerFactory")) {
                    hook(m, new XposedInterface.Hooker() {
                        @Override
                        public Object intercept(XposedInterface.Chain chain) throws Throwable {
                            return chain.proceed();
                        }
                    });
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private void hookInsecureTrustManagerFactory() {
        final String cn = "io.netty.handler.ssl.util.InsecureTrustManagerFactory";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".getTrustManagers", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("getTrustManagers")) {
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                return SSLFactory.trustAllManagers();
                            }
                        });
                    }
                }
            }
        });
    }

    // ---------------------------------------------------------------------
    //  gRPC OkHttp / Netty
    // ---------------------------------------------------------------------
    private void hookGrpcOkHttp() {
        final String cn = "io.grpc.okhttp.OkHttpChannelBuilder";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".sslSocketFactory", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("sslSocketFactory")) {
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                Object[] a = chain.getArgs().toArray();
                                a[0] = SSLFactory.getTrustAllSocketFactory();
                                return chain.proceed(a);
                            }
                        });
                    }
                }
            }
        });
    }

    private void hookGrpcNetty() {
        final String cn = "io.grpc.netty.NettyChannelBuilder";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".sslContext", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("sslContext")) {
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                return chain.proceed();
                            }
                        });
                    }
                }
            }
        });
    }

    // ---------------------------------------------------------------------
    //  BouncyCastle / 自研 TrustManager
    // ---------------------------------------------------------------------
    private void hookBouncyCastle() {
        String[] classNames = {
                "com.android.org.bouncycastle.jce.provider.PKIXCertPathValidatorSpi",
                "org.bouncycastle.jce.provider.PKIXCertPathValidatorSpi",
                "com.android.org.bouncycastle.jce.provider.CertPathValidatorUtilities"
        };
        for (final String cn : classNames) {
            if (!classExists(cn)) {
                continue;
            }
            tryHook(cn + ".engineValidate", new HookAction() {
                @Override
                public void run() throws Throwable {
                    Class<?> c = Class.forName(cn, false, cl);
                    int n = 0;
                    for (Method m : c.getDeclaredMethods()) {
                        String mn = m.getName();
                        if (mn.startsWith("engineValidate") || mn.startsWith("validate")) {
                            hook(m, new XposedInterface.Hooker() {
                                @Override
                                public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                    return chain.proceed();
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
