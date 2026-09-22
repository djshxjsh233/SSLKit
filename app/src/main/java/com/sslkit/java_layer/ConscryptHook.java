package com.sslkit.java_layer;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;
import com.sslkit.core.SSLFactory;

import java.lang.reflect.Method;
import java.util.List;

import io.github.libxposed.api.XposedInterface;

/**
 * L1 · Conscrypt —— Android 系统 TLS 实现。
 *
 * 重点：Platform.checkServerTrusted 是最底层入口，
 * Conscrypt 的 TrustManagerImpl 最终都会走到这里。
 */
public class ConscryptHook extends BaseHook {

    private static final String[] TRUST_IMPL = {
            "com.android.org.conscrypt.TrustManagerImpl",
            "org.conscrypt.TrustManagerImpl"
    };

    private static final String[] TRUST_METHODS = {
            "checkServerTrusted", "checkClientTrusted",
            "checkTrusted", "checkTrustedRecursive",
            "verifyChain", "getTrustedChainForServer"
    };

    public ConscryptHook(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    @Override
    public void install() {
        hookTrustManagerImpl();
        hookPlatform();
    }

    private void hookTrustManagerImpl() {
        for (final String cn : TRUST_IMPL) {
            if (!classExists(cn)) {
                continue;
            }
            tryHook(cn, new HookAction() {
                @Override
                public void run() throws Throwable {
                    Class<?> c = Class.forName(cn, false, cl);
                    hookMethodsByName(c, TRUST_METHODS, new XposedInterface.Hooker() {
                        @Override
                        public Object intercept(XposedInterface.Chain chain) throws Throwable {
                            List<Object> args = chain.getArgs();
                            Object first = args.isEmpty() ? null : args.get(0);
                            java.lang.reflect.Executable ex = chain.getExecutable();
                            Class<?> rt = (ex instanceof Method)
                                    ? ((Method) ex).getReturnType()
                                    : (ex instanceof java.lang.reflect.Constructor
                                    ? ((java.lang.reflect.Constructor<?>) ex).getDeclaringClass() : null);
                            return SSLFactory.bypassReturn(rt, first);
                        }
                    }, cn + ".all");
                }
            });
        }
    }

    /**
     * Platform.checkServerTrusted(X509TrustManager, X509Certificate[], String, <Socket 类型>)
     * 这是 Conscrypt 的底层入口，有 4 种 Socket 形态。
     */
    private void hookPlatform() {
        final String cn = "com.android.org.conscrypt.Platform";
        if (!classExists(cn)) {
            return;
        }
        tryHook("Platform.checkServerTrusted", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                int n = 0;
                for (Method m : c.getDeclaredMethods()) {
                    String mn = m.getName();
                    if (mn.equals("checkServerTrusted") || mn.equals("checkClientTrusted")) {
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
