package com.sslkit.java_layer;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;
import com.sslkit.core.SSLFactory;

import java.lang.reflect.Method;
import java.util.List;

import javax.net.ssl.X509TrustManager;

import io.github.libxposed.api.XposedInterface;

/**
 * L1 · X509ExtendedTrustManager（★ JustTrustMePro 完全没覆盖）。
 *
 * 现代 App（OkHttp 4+、部分银行类 App、Google 库）大量使用
 * X509ExtendedTrustManager，它是 X509TrustManager 的子接口，
 * 多了 checkServerTrusted(chain, authType, Socket/SSLEngine) 三个重载。
 *
 * 如果只 hook X509TrustManager，Java 虚拟机会走接口的具体实现类，
 * 那些带 Socket 参数的重载不会被拦到 —— 这是 JTM Pro 的盲区。
 */
public class ExtTrustManagerHook extends BaseHook {

    private static final String IFACE = "javax.net.ssl.X509ExtendedTrustManager";

    public ExtTrustManagerHook(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    @Override
    public void install() {
        if (!classExists(IFACE)) {
            com.sslkit.core.HookLogger.skip(IFACE, "class-not-found");
            return;
        }
        tryHook(IFACE + ".check*", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(IFACE, false, cl);
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
                    throw new NoSuchMethodException(IFACE);
                }
            }
        });

        // 顺带把 SSLParameters / SSLEngine 的 endpoint identification 关掉
        // （有些库用这个做 hostname 校验，绕过了 TrustManager）
        tryHook("SSLParameters.setEndpointIdentificationAlgorithm", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName("javax.net.ssl.SSLParameters", false, cl);
                Method m = c.getDeclaredMethod("setEndpointIdentificationAlgorithm", String.class);
                hook(m, new XposedInterface.Hooker() {
                    @Override
                    public Object intercept(XposedInterface.Chain chain) throws Throwable {
                        Object[] a = chain.getArgs().toArray();
                        a[0] = null;   // 关闭 endpoint identification
                        return chain.proceed(a);
                    }
                });
            }
        });

        // SSLParameters.setAlgorithmConstraints（少数库用约束拦算法）
        tryHook("X509TrustManager 接口兜底", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName("javax.net.ssl.X509TrustManager", false, cl);
                int n = 0;
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().startsWith("check")) {
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
                    throw new NoSuchMethodException("X509TrustManager");
                }
            }
        });
    }
}
