package com.sslkit.java_layer;

import com.sslkit.MainHook;
import com.sslkit.core.BaseHook;
import com.sslkit.core.SSLFactory;

import java.lang.reflect.Method;
import java.util.List;

import io.github.libxposed.api.XposedInterface;

/**
 * L1 · Android Network Security Config 层。
 *
 * android.security.net.config.NetworkSecurityTrustManager 是 Android 7+ 的
 * 网络安全配置执行者，APK 里 <pin-set> 声明的 pinning 就由它执行。
 *
 * 关键方法：
 *   checkServerTrusted(...)
 *   checkPins(List<Pin>)   ← pinning 检查
 *   verifyChain(...)
 */
public class NSCtrustHook extends BaseHook {

    private static final String CN = "android.security.net.config.NetworkSecurityTrustManager";

    private static final String[] METHODS = {
            "checkServerTrusted", "checkClientTrusted",
            "checkPins", "verifyChain"
    };

    public NSCtrustHook(MainHook module, ClassLoader cl) {
        super(module, cl);
    }

    @Override
    public void install() {
        if (!classExists(CN)) {
            skip(CN);
            return;
        }
        tryHook(CN, new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(CN, false, cl);
                hookMethodsByName(c, METHODS, new XposedInterface.Hooker() {
                    @Override
                    public Object intercept(XposedInterface.Chain chain) throws Throwable {
                        List<Object> args = chain.getArgs();
                        Object first = args.isEmpty() ? null : args.get(0);
                        java.lang.reflect.Executable ex = chain.getExecutable();
                        Class<?> rt = (ex instanceof Method) ? ((Method) ex).getReturnType() : null;
                        return SSLFactory.bypassReturn(rt, first);
                    }
                }, CN + ".all");
            }
        });
    }

    private void skip(String label) {
        com.sslkit.core.HookLogger.skip(label, "class-not-found");
    }
}
