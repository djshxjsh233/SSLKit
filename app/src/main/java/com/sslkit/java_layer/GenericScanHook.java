package com.sslkit.java_layer;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;
import com.sslkit.core.ClassScanner;
import com.sslkit.core.HookLogger;
import com.sslkit.core.SSLFactory;

import java.lang.reflect.Method;
import java.util.List;

import io.github.libxposed.api.XposedInterface;

/**
 * ★ 通用兜底 —— 把 ClassScanner 扫出来的可疑类全部 hook。
 *
 * 这是"通用性"的核心：不依赖写死的类名，
 * 新库 / 混淆库 / 自研库都能靠特征命中。
 */
public class GenericScanHook extends BaseHook {

    private final List<ClassScanner.Hit> hits;

    public GenericScanHook(MainHook module, ClassLoader cl, List<ClassScanner.Hit> hits) {
        super(module, cl);
        this.hits = hits;
    }

    @Override
    public void install() {
        if (hits == null || hits.isEmpty()) {
            HookLogger.skip("GenericScanHook", "no-hits");
            return;
        }
        module.info("[SSLKit] ClassScanner found " + hits.size() + " candidate classes");

        int count = 0;
        for (final ClassScanner.Hit hit : hits) {
            try {
                hookOne(hit);
                count++;
            } catch (Throwable t) {
                HookLogger.fail("Scan:" + hit.className, t);
            }
        }
        module.info("[SSLKit] GenericScanHook hooked " + count + "/" + hits.size());
    }

    private void hookOne(final ClassScanner.Hit hit) {
        // 跳过接口 / 抽象类（hook 不了）
        if (hit.clazz.isInterface()) {
            return;
        }
        boolean any = false;
        for (Method m : hit.clazz.getDeclaredMethods()) {
            if (m.isSynthetic() || m.isBridge()) {
                continue;
            }
            String mn = m.getName();
            if (!isCertCheckMethod(mn)) {
                continue;
            }
            if (!hasCertParam(m)) {
                continue;
            }
            try {
                final Method fm = m;
                hook(m, new XposedInterface.Hooker() {
                    @Override
                    public Object intercept(XposedInterface.Chain chain) throws Throwable {
                        List<Object> args = chain.getArgs();
                        Object first = args.isEmpty() ? null : args.get(0);
                        if (com.sslkit.Config.VERBOSE) {
                            module.info("[SSLKit][scan] hit " + fm.getDeclaringClass().getName()
                                    + "#" + fm.getName());
                        }
                        return SSLFactory.bypassReturn(fm.getReturnType(), first);
                    }
                });
                any = true;
            } catch (Throwable ignored) {
            }
        }
        if (any) {
            HookLogger.ok("Scan:" + hit.className);
        }
    }

    private boolean isCertCheckMethod(String mn) {
        return mn.startsWith("checkServerTrusted")
                || mn.startsWith("checkClientTrusted")
                || mn.startsWith("checkTrusted")
                || mn.equals("verifyChain")
                || mn.equals("verify")
                || mn.equals("verifyHostname")
                || mn.equals("checkPins")
                || mn.equals("isSecure")
                || mn.equals("validate");
    }

    private boolean hasCertParam(Method m) {
        for (Class<?> p : m.getParameterTypes()) {
            if (p == java.security.cert.X509Certificate.class
                    || p == java.security.cert.X509Certificate[].class
                    || p == java.security.cert.Certificate.class
                    || p == java.security.cert.Certificate[].class) {
                return true;
            }
            // CertificatePinner.findMatchingPins(String) 之类没有证书参数，
            // 但返回 List<Pin> —— 由 ClassScanner 的 reason 判断
        }
        return false;
    }
}
