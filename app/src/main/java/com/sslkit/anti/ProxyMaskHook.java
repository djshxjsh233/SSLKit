package com.sslkit.anti;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;

import java.lang.reflect.Method;
import java.util.List;

import io.github.libxposed.api.XposedInterface;

/**
 * L5 · 代理检测伪装（★ 方向与 JustTrustMePro 相反）。
 *
 * JustTrustMePro 的 ProxyHook 把 NO_PROXY 换成真实代理（想让 App 走代理），
 * 但很多 App 检测到"有代理"就主动拒连。SSLKit 反过来：
 * **让 App 以为环境干净、没有代理。**
 *
 * 覆盖：
 *   System.getProperty("http.proxyHost" / "https.proxyHost" / "http.proxyPort")
 *   ProxySelector.getDefault()
 *   ConnectivityManager.getDefaultProxy()
 *   LinkProperties.getHttpProxy()
 *   Settings.Global.getInt/getString("http_proxy")
 */
public class ProxyMaskHook extends BaseHook {

    private static final String[] PROXY_PROPS = {
            "http.proxyHost", "https.proxyHost", "http.proxyPort", "https.proxyPort",
            "socksProxyHost", "socksProxyPort"
    };

    public ProxyMaskHook(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    @Override
    public void install() {
        hookSystemProperties();
        hookProxySelector();
        hookConnectivityManager();
        hookLinkProperties();
        hookGlobalSettings();
    }

    private void hookSystemProperties() {
        tryHook("System.getProperty(proxy*)", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName("java.lang.System", false, cl);
                Method m1 = c.getDeclaredMethod("getProperty", String.class);
                Method m2 = c.getDeclaredMethod("getProperty", String.class, String.class);
                XposedInterface.Hooker h = new XposedInterface.Hooker() {
                    @Override
                    public Object intercept(XposedInterface.Chain chain) throws Throwable {
                        List<Object> args = chain.getArgs();
                        Object k = args.isEmpty() ? null : args.get(0);
                        if (k instanceof String && isProxyKey((String) k)) {
                            return null;
                        }
                        return chain.proceed();
                    }
                };
                hook(m1, h);
                hook(m2, h);
            }
        });
    }

    private static boolean isProxyKey(String k) {
        for (String p : PROXY_PROPS) {
            if (p.equalsIgnoreCase(k)) {
                return true;
            }
        }
        return k.toLowerCase().contains("proxy");
    }

    private void hookProxySelector() {
        final String cn = "sun.net.spi.DefaultProxySelector";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".select", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("select")) {
                        final Class<?> rt = m.getReturnType();
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                // 返回 [Proxy.NO_PROXY]
                                java.util.List<Object> out = new java.util.ArrayList<Object>();
                                out.add(java.net.Proxy.NO_PROXY);
                                return out;
                            }
                        });
                    }
                }
            }
        });
    }

    private void hookConnectivityManager() {
        final String cn = "android.net.ConnectivityManager";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".getDefaultProxy", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("getDefaultProxy")) {
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                return null;
                            }
                        });
                    }
                }
            }
        });
    }

    private void hookLinkProperties() {
        final String cn = "android.net.LinkProperties";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".getHttpProxy", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("getHttpProxy")) {
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                return null;
                            }
                        });
                    }
                }
            }
        });
    }

    private void hookGlobalSettings() {
        final String cn = "android.provider.Settings$Global";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".getString(http_proxy)", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                for (Method m : c.getDeclaredMethods()) {
                    String mn = m.getName();
                    if (!mn.equals("getString") && !mn.equals("getInt")) {
                        continue;
                    }
                    hook(m, new XposedInterface.Hooker() {
                        @Override
                        public Object intercept(XposedInterface.Chain chain) throws Throwable {
                            List<Object> args = chain.getArgs();
                            if (args.size() >= 2) {
                                Object name = args.get(1);
                                if (name instanceof String) {
                                    String n = (String) name;
                                    if (n.contains("proxy")) {
                                        return mnIsInt(chain) ? Integer.valueOf(-1) : null;
                                    }
                                }
                            }
                            return chain.proceed();
                        }
                    });
                }
            }
        });
    }

    private static boolean mnIsInt(XposedInterface.Chain chain) {
        try {
            String n = chain.getExecutable().toString();
            return n.contains("getInt");
        } catch (Throwable ignored) {
        }
        return false;
    }
}
