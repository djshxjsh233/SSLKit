package com.sslkit.java_layer;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;
import com.sslkit.core.SSLFactory;

import java.lang.reflect.Method;
import java.util.List;

import io.github.libxposed.api.XposedInterface;

/**
 * L1 · TrustManager 补充覆盖。
 *
 * 与 SSLContextHook 的分工：
 *   SSLContextHook   → SSLContext.init / TMF / HttpsURLConnection / 系统实现类
 *   TrustManagerHook → 第三方 / 自研 / 变体 TrustManager + HostnameVerifier + SSLSocket 层
 *
 * 覆盖：
 *   javax.net.ssl.HostnameVerifier.verify
 *   javax.net.ssl.SSLSession          相关
 *   android.net.http.X509TrustManagerExtensions.checkServerTrusted
 *   okhttp3.internal.connection.RealConnection.createTunnel（代理隧道场景）
 *   SSLSocket.startHandshake 之后的 hostname 校验
 *   Conscrypt 的 OpenSSLSocketImpl.verifyCertificateChain
 */
public class TrustManagerHook extends BaseHook {

    public TrustManagerHook(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    @Override
    public void install() {
        hookHostnameVerifier();
        hookX509TrustManagerExtensions();
        hookOkHttpRealConnection();
        hookConscryptSocket();
        hookOkHostnameVerifier();
    }

    /** HostnameVerifier.verify 全放行 */
    private void hookHostnameVerifier() {
        final String cn = "javax.net.ssl.HostnameVerifier";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".verify", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("verify")) {
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

    /** android.net.http.X509TrustManagerExtensions */
    private void hookX509TrustManagerExtensions() {
        final String cn = "android.net.http.X509TrustManagerExtensions";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".checkServerTrusted", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                int n = 0;
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("checkServerTrusted")
                            || m.getName().equals("isUserAddedCertificate")) {
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

    /** OkHttp RealConnection.createTunnel（CONNECT 代理隧道时会重做 TLS 校验） */
    private void hookOkHttpRealConnection() {
        final String cn = "okhttp3.internal.connection.RealConnection";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".createTunnel", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("createTunnel")) {
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

    /** Conscrypt 的 socket 层校验 */
    private void hookConscryptSocket() {
        String[] classNames = {
                "com.android.org.conscrypt.OpenSSLSocketImpl",
                "com.android.org.conscrypt.ConscryptEngineSocket",
                "com.android.org.conscrypt.OpenSSLEngineImpl"
        };
        for (final String cn : classNames) {
            if (!classExists(cn)) {
                continue;
            }
            tryHook(cn + ".verifyCertificateChain", new HookAction() {
                @Override
                public void run() throws Throwable {
                    Class<?> c = Class.forName(cn, false, cl);
                    int n = 0;
                    for (Method m : c.getDeclaredMethods()) {
                        if (m.getName().contains("verifyCertificateChain")
                                || m.getName().equals("checkServerTrusted")) {
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
    }

    /** OkHostnameVerifier（OkHttp 自带 hostname 校验） */
    private void hookOkHostnameVerifier() {
        String[] classNames = {
                "okhttp3.internal.tls.OkHostnameVerifier",
                "okhttp3.OkHostnameVerifier"
        };
        for (final String cn : classNames) {
            if (!classExists(cn)) {
                continue;
            }
            tryHook(cn + ".verify*", new HookAction() {
                @Override
                public void run() throws Throwable {
                    Class<?> c = Class.forName(cn, false, cl);
                    int n = 0;
                    for (Method m : c.getDeclaredMethods()) {
                        if (m.getName().startsWith("verify")
                                || m.getName().equals("verifyHostname")) {
                            hook(m, new XposedInterface.Hooker() {
                                @Override
                                public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                    return Boolean.TRUE;
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
