package com.sslkit.core;

import com.sslkit.Config;
import com.sslkit.MainHook;

import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import io.github.libxposed.api.XposedInterface;

/**
 * BaseHook —— 所有 hook 的基类（libxposed API 102）。
 *
 * API 102 要点：
 *  - hook 的入参是 java.lang.reflect.Executable（Method / Constructor 都是）
 *  - 用 module.hook(executable).intercept(Hooker) 注册
 *  - Hooker.intercept(Chain) 里用 chain.getArgs() / chain.proceed(Object[])
 */
public abstract class BaseHook {

    protected final MainHook module;
    protected final ClassLoader cl;
    protected final String name;

    protected BaseHook(MainHook module, ClassLoader cl) {
        this.module = module;
        this.cl = cl;
        this.name = getClass().getSimpleName();
    }

    /** 子类实现具体 hook 逻辑 */
    public abstract void install();

    // =====================================================================
    //  hook 封装
    // =====================================================================

    /** 底层：hook 一个 Executable，用指定拦截器 */
    protected void hook(Executable ex, XposedInterface.Hooker hooker) {
        ex.setAccessible(true);
        module.hook(ex).intercept(hooker);
    }

    /** 底层：hook 一个 Executable，直接放行（占位用） */
    protected void hookPassThrough(Executable ex) {
        hook(ex, new XposedInterface.Hooker() {
            @Override
            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                return chain.proceed();
            }
        });
    }

    /** 替换某方法的返回值 */
    protected XposedInterface.Hooker hookReturn(final Object value) {
        return new XposedInterface.Hooker() {
            @Override
            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                Class<?> rt = chain.getExecutable() instanceof Method
                        ? ((Method) chain.getExecutable()).getReturnType() : null;
                if (rt == void.class) {
                    return null;
                }
                return value;
            }
        };
    }

    /**
     * 按 "类名 + 方法名 + 参数类型" hook。
     * paramTypes 可为 Class 或 Class 名字符串。
     */
    protected void hookMethod(final String className, final String methodName, Object... paramTypes) {
        tryHook(className + "#" + methodName, new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(className, false, cl);
                Method m = findMethod(c, methodName, toClasses(paramTypes));
                if (m == null) {
                    throw new NoSuchMethodException(className + "#" + methodName);
                }
                hook(m, passThrough());
            }
        });
    }

    /** 按签名 hook，并带自定义拦截器 */
    protected void hookMethodWith(final String className, final String methodName,
                                  final XposedInterface.Hooker hooker, Object... paramTypes) {
        tryHook(className + "#" + methodName, new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(className, false, cl);
                Method m = findMethod(c, methodName, toClasses(paramTypes));
                if (m == null) {
                    throw new NoSuchMethodException(className + "#" + methodName);
                }
                hook(m, hooker);
            }
        });
    }

    /**
     * hook 某类里所有同名方法（不关心参数）。
     */
    protected void hookAllMethods(final String className, final String methodName,
                                  final XposedInterface.Hooker hooker) {
        tryHook(className + "#" + methodName + "(*)", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(className, false, cl);
                int n = 0;
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals(methodName) && !m.isSynthetic()) {
                        hook(m, hooker);
                        n++;
                    }
                }
                if (n == 0) {
                    throw new NoSuchMethodException(methodName);
                }
            }
        });
    }

    /**
     * 用同一个拦截器 hook 某类里名字在集合中的所有方法。
     */
    protected void hookMethodsByName(final Class<?> c, final String[] methodNames,
                                     final XposedInterface.Hooker hooker, final String label) {
        tryHook(label, new HookAction() {
            @Override
            public void run() throws Throwable {
                int n = 0;
                for (Method m : c.getDeclaredMethods()) {
                    if (m.isSynthetic()) {
                        continue;
                    }
                    for (String mn : methodNames) {
                        if (m.getName().equals(mn)) {
                            hook(m, hooker);
                            n++;
                            break;
                        }
                    }
                }
                if (n == 0) {
                    throw new NoSuchMethodException(c.getName());
                }
            }
        });
    }

    /** hook 构造器 */
    protected void hookConstructor(final String className, final XposedInterface.Hooker hooker,
                                   Object... paramTypes) {
        tryHook(className + "#<init>", new HookAction() {
            @Override
            public void run() throws Throwable {
                Class<?> c = Class.forName(className, false, cl);
                Class<?>[] pts = toClasses(paramTypes);
                Constructor<?> ctor = (pts == null || pts.length == 0)
                        ? c.getDeclaredConstructor()
                        : c.getDeclaredConstructor(pts);
                hook(ctor, hooker);
            }
        });
    }

    // =====================================================================
    //  工具
    // =====================================================================

    /** 直通拦截器（什么都不做） */
    protected XposedInterface.Hooker passThrough() {
        return new XposedInterface.Hooker() {
            @Override
            public Object intercept(XposedInterface.Chain chain) throws Throwable {
                return chain.proceed();
            }
        };
    }

    private static Method findMethod(Class<?> c, String name, Class<?>[] types) {
        Class<?> cur = c;
        while (cur != null && cur != Object.class) {
            try {
                if (types == null || types.length == 0) {
                    return cur.getDeclaredMethod(name);
                }
                boolean ok = true;
                for (Class<?> t : types) {
                    if (t == null) {
                        ok = false;
                        break;
                    }
                }
                if (ok) {
                    return cur.getDeclaredMethod(name, types);
                }
            } catch (Throwable ignored) {
            }
            cur = cur.getSuperclass();
        }
        return null;
    }

    protected Class<?>[] toClasses(Object[] raw) {
        if (raw == null) {
            return new Class<?>[0];
        }
        List<Class<?>> out = new ArrayList<Class<?>>();
        for (Object o : raw) {
            if (o instanceof Class) {
                out.add((Class<?>) o);
            } else if (o instanceof String) {
                try {
                    out.add(Class.forName((String) o, false, cl));
                } catch (Throwable t) {
                    out.add(null);
                }
            } else {
                out.add(null);
            }
        }
        return out.toArray(new Class<?>[0]);
    }

    protected void tryHook(String label, HookAction action) {
        try {
            action.run();
            HookLogger.ok(label);
            if (Config.VERBOSE) {
                module.info("[SSLKit][+] " + label);
            }
        } catch (Throwable t) {
            HookLogger.fail(label, t);
            if (Config.VERBOSE) {
                module.logError("[SSLKit][!] " + label, t);
            }
        }
    }

    protected boolean classExists(String className) {
        try {
            Class.forName(className, false, cl);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    protected Class<?> loadClass(String className) {
        try {
            return Class.forName(className, false, cl);
        } catch (Throwable t) {
            return null;
        }
    }

    public interface HookAction {
        void run() throws Throwable;
    }
}
