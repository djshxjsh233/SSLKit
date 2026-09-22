package com.sslkit.ui;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.sslkit.Config;
import com.sslkit.MainHook;
import com.sslkit.native_layer.NativeHookInstaller;

/**
 * 模块主界面 —— 分层开关 + 状态展示。
 *
 * 极简实现：不用 layout xml，纯 Java 构建视图，避免资源编译问题。
 */
public class MainActivity extends Activity {

    private static final String PREF = "sslkit_config";

    private SharedPreferences sp;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        sp = getSharedPreferences(PREF, MODE_PRIVATE);

        ScrollView sv = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);
        sv.addView(root);

        // 标题
        TextView title = new TextView(this);
        title.setText("SSLKit v" + MainHook.VERSION + "  —  通用 SSL Pinning 绕过");
        title.setTextSize(18);
        title.setPadding(0, 0, 0, pad);
        root.addView(title);

        // 说明
        TextView desc = new TextView(this);
        desc.setText("勾选要启用的层，然后重启目标 App。\n"
                + "作用域在 LSPosed 里勾选（本模块不使用 staticScope）。");
        desc.setTextSize(12);
        desc.setPadding(0, 0, 0, pad * 2);
        root.addView(desc);

        // ---------- 分层开关 ----------
        addSwitch(root, "L1 · Java 层", "SSLContext / TrustManager / OkHttp / Conscrypt / Netty",
                "l1", Config.L1_JAVA);
        addSwitch(root, "L2 · Native 层 ★", "BoringSSL 符号 hook（字节 / Flutter / 游戏必需）",
                "l2", Config.L2_NATIVE);
        addSwitch(root, "L3 · Dart / Flutter", "Flutter 检测（依赖 L2 生效）",
                "l3", Config.L3_DART);
        addSwitch(root, "L4 · WebView / H5", "onReceivedSslError + X5 + 全类扫描",
                "l4", Config.L4_WEBVIEW);
        addSwitch(root, "L5 · 反检测", "伪装无代理 / 无 VPN（防抓包被检测而断网）",
                "l5", Config.L5_ANTIDETECT);

        // 细项
        TextView sub = new TextView(this);
        sub.setText("\n—— 细项 ——");
        sub.setTextSize(14);
        root.addView(sub);

        addSwitch(root, "全量类扫描", "扫 dex 里所有可疑证书校验类（通用性最强，稍慢）",
                "scan", Config.FULL_CLASS_SCAN);
        addSwitch(root, "Cronet 专杀", "Cronet_CertVerify_DoVerifyV2 + AndroidCertVerifyResult",
                "cronet", Config.CRONET_KILL);
        addSwitch(root, "OkHttp 混淆版定位", "按字段特征定位混淆后的 OkHttp",
                "okobf", Config.OKHTTP_OBFUSCATED);
        addSwitch(root, "详细日志", "打印每次命中（排错用）",
                "verbose", Config.VERBOSE);

        // 状态
        TextView st = new TextView(this);
        st.setText("\n—— 运行状态 ——\n"
                + "Native so: " + (NativeHookInstaller.isLoaded() ? "已加载" : "未加载") + "\n"
                + "提示：状态需在目标 App 进程里查看，此处为模块自身进程。");
        st.setTextSize(12);
        st.setPadding(0, pad, 0, 0);
        root.addView(st);

        setContentView(sv);
    }

    private void addSwitch(LinearLayout root, String label, String sub, final String key,
                           boolean def) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (8 * getResources().getDisplayMetrics().density);
        row.setPadding(0, pad, 0, pad);

        final CheckBox cb = new CheckBox(this);
        cb.setText(label);
        cb.setChecked(sp.getBoolean(key, def));
        cb.setOnCheckedChangeListener((buttonView, isChecked) ->
                sp.edit().putBoolean(key, isChecked).apply());
        row.addView(cb);

        if (sub != null) {
            TextView tv = new TextView(this);
            tv.setText("     " + sub);
            tv.setTextSize(11);
            tv.setAlpha(0.7f);
            row.addView(tv);
        }
        root.addView(row);
    }
}
