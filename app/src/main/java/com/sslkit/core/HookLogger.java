package com.sslkit.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Hook 命中统计 + 日志。
 */
public final class HookLogger {

    private static final Map<String, String> RESULTS = Collections.synchronizedMap(new LinkedHashMap<String, String>());
    private static String pkg = "";

    public static void reset(String packageName) {
        pkg = packageName;
        RESULTS.clear();
    }

    public static void ok(String name) {
        RESULTS.put(name, "OK");
    }

    public static void skip(String name, String reason) {
        RESULTS.put(name, "SKIP(" + reason + ")");
    }

    public static void fail(String name, Throwable t) {
        String m = t == null ? "?" : (t.getClass().getSimpleName() + ": " + t.getMessage());
        if (m.length() > 80) {
            m = m.substring(0, 80);
        }
        RESULTS.put(name, "FAIL(" + m + ")");
    }

    public static String summary() {
        int ok = 0, skip = 0, fail = 0;
        List<String> detail = new ArrayList<String>();
        synchronized (RESULTS) {
            for (Map.Entry<String, String> e : RESULTS.entrySet()) {
                String v = e.getValue();
                if (v.equals("OK")) {
                    ok++;
                } else if (v.startsWith("SKIP")) {
                    skip++;
                } else {
                    fail++;
                }
                detail.add("  " + (v.equals("OK") ? "[+]" : v.startsWith("SKIP") ? "[-]" : "[!]")
                        + " " + e.getKey() + " -> " + v);
            }
        }
        StringBuilder sb = new StringBuilder();
        sb.append("[SSLKit] hook summary for ").append(pkg)
                .append(": OK=").append(ok).append(" SKIP=").append(skip).append(" FAIL=").append(fail);
        for (String d : detail) {
            sb.append('\n').append(d);
        }
        return sb.toString();
    }

    public static Map<String, String> raw() {
        return RESULTS;
    }

    private HookLogger() {
    }
}
