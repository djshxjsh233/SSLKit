package com.sslkit.anti;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;

import java.lang.reflect.Method;
import java.util.List;

import io.github.libxposed.api.XposedInterface;

/**
 * L5 · VPN / tun 检测伪装。
 *
 * App 常用这些方式判断"当前在网络代理/VPN 环境"：
 *   NetworkCapabilities.hasTransport(TRANSPORT_VPN)
 *   NetworkInterface.getNetworkInterfaces() 里有没有 tun0/ppp0
 *   ConnectivityManager.getNetworkCapabilities() 里的 TRANSPORT_VPN
 *   LinkProperties.getInterfaceName() == tun0
 *
 * 伪装策略：让这些调用返回"没有 VPN"。
 *
 * ⚠️ 注意：本层只解决"因为抓包环境被检测而断网"，
 *    **不做 root / 隐藏 root**（那是 Shamiko / HideMyAppList 的活）。
 */
public class VpnMaskHook extends BaseHook {

    public VpnMaskHook(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    @Override
    public void install() {
        hookNetworkCapabilities();
        hookNetworkInterface();
        hookLinkProperties();
        hookVpnService();
    }

    private void hookNetworkCapabilities() {
        final String cn = "android.net.NetworkCapabilities";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".hasTransport", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("hasTransport")) {
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                List<Object> args = chain.getArgs();
                                if (!args.isEmpty() && args.get(0) instanceof Integer) {
                                    int t = (Integer) args.get(0);
                                    // TRANSPORT_VPN = 4
                                    if (t == 4) {
                                        return Boolean.FALSE;
                                    }
                                }
                                return chain.proceed();
                            }
                        });
                    }
                }
            }
        });

        tryHook(cn + ".hasCapability", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("hasCapability")) {
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

    private void hookNetworkInterface() {
        final String cn = "java.net.NetworkInterface";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".getNetworkInterfaces", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                Method m = c.getDeclaredMethod("getNetworkInterfaces");
                hook(m, new XposedInterface.Hooker() {
                    @Override
                    public Object intercept(XposedInterface.Chain chain) throws Throwable {
                        Object r = chain.proceed();
                        if (!(r instanceof java.util.Enumeration)) {
                            return r;
                        }
                        java.util.Enumeration<?> en = (java.util.Enumeration<?>) r;
                        java.util.List<Object> keep = new java.util.ArrayList<Object>();
                        while (en.hasMoreElements()) {
                            Object ni = en.nextElement();
                            try {
                                String nm = (String) ni.getClass().getMethod("getName").invoke(ni);
                                if (isVpnIface(nm)) {
                                    continue;
                                }
                            } catch (Throwable ignored) {
                            }
                            keep.add(ni);
                        }
                        return java.util.Collections.enumeration(keep);
                    }
                });
            }
        });
    }

    private static boolean isVpnIface(String name) {
        if (name == null) {
            return false;
        }
        String n = name.toLowerCase();
        return n.startsWith("tun") || n.startsWith("tap") || n.startsWith("ppp")
                || n.startsWith("utun") || n.startsWith("wg") || n.equals("rmnet_ipa0");
    }

    private void hookLinkProperties() {
        final String cn = "android.net.LinkProperties";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".getInterfaceName", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("getInterfaceName")) {
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                Object r = chain.proceed();
                                if (r instanceof String && isVpnIface((String) r)) {
                                    return "wlan0";
                                }
                                return r;
                            }
                        });
                    }
                }
            }
        });
    }

    private void hookVpnService() {
        final String cn = "android.net.VpnService";
        if (!classExists(cn)) {
            return;
        }
        tryHook(cn + ".isPrepared", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(cn, false, cl);
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("isPrepared")) {
                        hook(m, new XposedInterface.Hooker() {
                            @Override
                            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                                return Boolean.FALSE;
                            }
                        });
                    }
                }
            }
        });
    }
}
