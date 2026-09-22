package com.sslkit.core;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * trustAll 工厂 —— 提供各种"什么都信"的 SSL 对象。
 *
 * 关键设计（吸收 JustTrustMePro 的教训）：
 *  - bypassReturn(returnType, certsArg) 按返回类型动态造返回值
 *    → void 返回 null；List 返回 List；数组返回数组
 *    → WebView 要 List 不要空数组，空数组在新版 Chromium 上是硬失败
 */
public final class SSLFactory {

    private static SSLContext sTrustAllContext;
    private static SSLSocketFactory sTrustAllFactory;
    private static X509TrustManager sTrustAllTM;

    public static void warmUp() {
        try {
            getTrustAllContext();
        } catch (Throwable ignored) {
        }
    }

    public static synchronized X509TrustManager getTrustAllTM() {
        if (sTrustAllTM == null) {
            sTrustAllTM = new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };
        }
        return sTrustAllTM;
    }

    public static synchronized SSLContext getTrustAllContext() {
        if (sTrustAllContext == null) {
            try {
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, new TrustManager[]{getTrustAllTM()}, new SecureRandom());
                sTrustAllContext = ctx;
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (KeyManagementException e) {
                throw new RuntimeException(e);
            }
        }
        return sTrustAllContext;
    }

    public static synchronized SSLSocketFactory getTrustAllSocketFactory() {
        if (sTrustAllFactory == null) {
            sTrustAllFactory = new WrappedFactory(getTrustAllContext().getSocketFactory());
        }
        return sTrustAllFactory;
    }

    /**
     * TrustManager 数组，供 SSLContext.init 的 before 阶段替换。
     */
    public static TrustManager[] trustAllManagers() {
        return new TrustManager[]{getTrustAllTM()};
    }

    public static HostnameVerifier trustAllHostnameVerifier() {
        return new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
    }

    /**
     * 按原方法返回类型，造一个"校验通过"的返回值。
     *
     * @param returnType 原方法返回类型
     * @param certsArg   原方法第一个参数（证书链）
     */
    public static Object bypassReturn(Class<?> returnType, Object certsArg) {
        if (returnType == null || returnType == void.class || returnType == Void.class) {
            return null;
        }
        List<X509Certificate> certs = certsToList(certsArg);

        // List / MutableList（WebView 要这个）
        if (List.class.isAssignableFrom(returnType)) {
            return certs;
        }
        if (Collection.class.isAssignableFrom(returnType)) {
            return certs;
        }
        // 数组
        if (returnType.isArray()) {
            Class<?> comp = returnType.getComponentType();
            if (comp == X509Certificate.class
                    || comp == java.security.cert.Certificate.class
                    || comp == Object.class) {
                return certs.toArray(new X509Certificate[0]);
            }
        }
        // boolean / Boolean
        if (returnType == boolean.class || returnType == Boolean.class) {
            return Boolean.TRUE;
        }
        // int / Integer（checkPins 等返回 0 = OK）
        if (returnType == int.class || returnType == Integer.class) {
            return 0;
        }
        // long
        if (returnType == long.class || returnType == Long.class) {
            return 0L;
        }
        // String：hostname verifier 之类
        if (returnType == String.class) {
            return "";
        }
        // 其他对象类型：返回 null（多数校验方法无返回值语义）
        return null;
    }

    public static List<X509Certificate> certsToList(Object arg) {
        List<X509Certificate> out = new ArrayList<X509Certificate>();
        if (arg == null) {
            return out;
        }
        if (arg instanceof Object[]) {
            for (Object o : (Object[]) arg) {
                if (o instanceof X509Certificate) {
                    out.add((X509Certificate) o);
                }
            }
        } else if (arg instanceof Collection) {
            for (Object o : (Collection<?>) arg) {
                if (o instanceof X509Certificate) {
                    out.add((X509Certificate) o);
                }
            }
        }
        return out;
    }

    /**
     * 包一层 SSLSocketFactory。
     *
     * 有些库会 `if (!(factory instanceof ItsOwnFactory))` 做类型判断，
     * 直接换成 SSLSocketFactory 可能被识破 → 这里保留委托，行为仍为 trustAll。
     */
    private static final class WrappedFactory extends SSLSocketFactory {
        private final SSLSocketFactory delegate;

        WrappedFactory(SSLSocketFactory delegate) {
            this.delegate = delegate;
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return delegate.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return delegate.getSupportedCipherSuites();
        }

        @Override
        public java.net.Socket createSocket(java.net.Socket s, String host, int port, boolean autoClose)
                throws java.io.IOException {
            return delegate.createSocket(s, host, port, autoClose);
        }

        @Override
        public java.net.Socket createSocket(String host, int port)
                throws java.io.IOException, java.net.UnknownHostException {
            return delegate.createSocket(host, port);
        }

        @Override
        public java.net.Socket createSocket(String host, int port, java.net.InetAddress localHost, int localPort)
                throws java.io.IOException, java.net.UnknownHostException {
            return delegate.createSocket(host, port, localHost, localPort);
        }

        @Override
        public java.net.Socket createSocket(java.net.InetAddress host, int port)
                throws java.io.IOException {
            return delegate.createSocket(host, port);
        }

        @Override
        public java.net.Socket createSocket(java.net.InetAddress address, int port,
                                            java.net.InetAddress localAddress, int localPort)
                throws java.io.IOException {
            return delegate.createSocket(address, port, localAddress, localPort);
        }
    }

    private SSLFactory() {
    }
}
