package com.sslkit.web;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;
import com.sslkit.core.ClassScanner;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import io.github.libxposed.api.XposedInterface;

/**
 * L4 · WebView / H5（吸收 JustTrustMePro 并加强）。
 *
 * 覆盖：
 *   android.webkit.WebViewClient.onReceivedSslError      → handler.proceed()
 *   android.webkit.WebViewClient.onReceivedError         → 吞掉
 *   com.tencent.smtt.sdk.WebViewClient.onReceivedSslError (X5)
 *   com.tencent.smtt.sdk.SystemWebViewClient.onReceivedError (X5)
 *   ★ 全类扫描：所有含 onReceivedSslError 的类（替换 JTM Pro 的"猜类名"）
 *   ★ onReceivedClientCertRequest（客户端证书）
 */
public class WebViewHook extends BaseHook {

    public WebViewHook(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    @Override
    public void install() {
        hookSystemWebView();
        hookTencentX5();
        hookByScan();
        hookClientCert();
    }

    private void hookSystemWebView() {
        final String cn = "android.webkit.WebViewClient";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".onReceivedSslError", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                int n = 0;
                for (Method m : c.getDeclaredMethods()) {
                    String mn = m.getName();
                    if (mn.equals("onReceivedSslError")) {
                        hook(m, proceedSslError());
                        n++;
                    } else if (mn.equals("onReceivedError")) {
                        hook(m, swallow());
                        n++;
                    }
                }
                if (n == 0) {
                    throw new NoSuchMethodException(cn);
                }
            }
        });
    }

    private void hookTencentX5() {
        String[] classNames = {
                "com.tencent.smtt.sdk.WebViewClient",
                "com.tencent.smtt.sdk.SystemWebViewClient"
        };
        for (final String cn : classNames) {
            if (!classExists(cn)) {
                continue;
            }
            tryHook(cn, new HookAction() {
                @Override
                public void run() throws Throwable {
                    Class<?> c = Class.forName(cn, false, cl);
                    int n = 0;
                    for (Method m : c.getDeclaredMethods()) {
                        String mn = m.getName();
                        if (mn.equals("onReceivedSslError")) {
                            hook(m, proceedSslErrorReflect());
                            n++;
                        } else if (mn.equals("onReceivedError")) {
                            hook(m, swallow());
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

    /**
     * ★ 全类扫描：找所有声明了 onReceivedSslError 的类（自研 WebViewClient、混淆过的）。
     */
    private void hookByScan() {
        tryHook("WebView 全类扫描 onReceivedSslError", new HookAction() {
            @Override
            public void run() throws Throwable {
                List<Class<?>> found = new ArrayList<Class<?>>();
                try {
                    java.util.Set<String> names = ClassScanner.allClassNames(cl);
                    for (String n : names) {
                        if (n == null || n.indexOf('$') >= 0) {
                            continue;
                        }
                        String lower = n.toLowerCase();
                        if (lower.indexOf("webview") < 0 && lower.indexOf("webclient") < 0
                                && lower.indexOf("webchrome") < 0) {
                            continue;
                        }
                        try {
                            Class<?> c = Class.forName(n, false, cl);
                            for (Method m : c.getDeclaredMethods()) {
                                if (m.getName().equals("onReceivedSslError")) {
                                    found.add(c);
                                    break;
                                }
                            }
                        } catch (Throwable ignored) {
                        }
                    }
                } catch (Throwable ignored) {
                }

                int n = 0;
                for (Class<?> c : found) {
                    for (Method m : c.getDeclaredMethods()) {
                        if (m.getName().equals("onReceivedSslError")) {
                            hook(m, proceedSslErrorReflect());
                            n++;
                        }
                    }
                }
                if (n == 0) {
                    throw new NoSuchMethodException("no scanned WebViewClient");
                }
                module.info("[SSLKit] WebView scan hooked " + n + " onReceivedSslError");
            }
        });
    }

    private void hookClientCert() {
        final String cn = "android.webkit.WebViewClient";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".onReceivedClientCertRequest", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                int n = 0;
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("onReceivedClientCertRequest")) {
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                // 反射调用 arg.cancel() / proceed(null,null)
                                List<Object> args = chain.getArgs();
                                if (args.size() >= 2) {
                                    Object req = args.get(1);
                                    try {
                                        if (req != null) {
                                            req.getClass().getMethod("cancel").invoke(req);
                                        }
                                    } catch (Throwable ignored) {
                                    }
                                }
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

    // ---------------------------------------------------------------------
    //  中间件
    // ---------------------------------------------------------------------

    private XposedInterface.Hooker swallow() {
        return new XposedInterface.Hooker() {
            @Override
            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                return null;
            }
        };
    }

    /** android.webkit.SslErrorHandler 直接强转 */
    private XposedInterface.Hooker proceedSslError() {
        return new XposedInterface.Hooker() {
            @Override
            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                List<Object> args = chain.getArgs();
                if (args.size() >= 2) {
                    Object h = args.get(1);
                    if (h instanceof android.webkit.SslErrorHandler) {
                        ((android.webkit.SslErrorHandler) h).proceed();
                        return null;
                    }
                }
                return chain.proceed();
            }
        };
    }

    /** X5 的 SslErrorHandler 类型不同，用反射调 proceed() */
    private XposedInterface.Hooker proceedSslErrorReflect() {
        return new XposedInterface.Hooker() {
            @Override
            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                List<Object> args = chain.getArgs();
                for (Object a : args) {
                    if (a == null) {
                        continue;
                    }
                    String cn = a.getClass().getName();
                    if (cn.contains("SslErrorHandler")) {
                        try {
                            a.getClass().getMethod("proceed").invoke(a);
                            return null;
                        } catch (Throwable ignored) {
                        }
                    }
                }
                return null;
            }
        };
    }
}
