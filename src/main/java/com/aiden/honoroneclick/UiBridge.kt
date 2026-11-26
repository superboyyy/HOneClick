package com.aiden.honoroneclick

import android.os.Build
import android.system.Os
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.ComposeView
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

const val APP_VERSION_LABEL = BuildConfig.VERSION_NAME

enum class StageStatus {
    RUNNING,
    DONE,
    FAILED
}

enum class StatusTone {
    IDLE,
    WARNING,
    READY,
    RUNNING,
    SUCCESS,
    ERROR
}

data class StageProgress(
    val title: String,
    val status: StageStatus,
    val durationMs: Long,
    val startedAt: Long
)

data class LogEntry(
    val timestamp: String,
    val message: String,
    val isError: Boolean
)

enum class ExploitChoice(val label: String) {
    AUTO("自动"),
    CVE_99491("99491"),
    CVE_98260("98260")
}

data class SupportedKernelSpec(
    val index: Int,
    val version: String,
    val routes: List<ExploitChoice>,
    val preferredRoute: ExploitChoice
)

object SupportedKernels {
    val entries: List<SupportedKernelSpec> = listOf(
        SupportedKernelSpec(
            index = 1,
            version = "6.18.21-android17-5-gfee2325de189-abogki572422516-4k",
            routes = listOf(ExploitChoice.CVE_99491, ExploitChoice.CVE_98260),
            preferredRoute = ExploitChoice.CVE_99491
        ),
        SupportedKernelSpec(
            index = 2,
            version = "6.18.21-android17-5-ge186062ea75f-abogki564062290-4k",
            routes = listOf(ExploitChoice.CVE_98260),
            preferredRoute = ExploitChoice.CVE_98260
        ),
        SupportedKernelSpec(
            index = 3,
            version = "6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k",
            routes = listOf(ExploitChoice.CVE_98260),
            preferredRoute = ExploitChoice.CVE_98260
        )
    )

    @JvmStatic
    fun find(kernel: String?): SupportedKernelSpec? {
        if (kernel.isNullOrBlank()) return null
        val trimmed = kernel.trim()
        return entries.firstOrNull { it.version == trimmed }
    }

    @JvmStatic
    fun supports99491(kernel: String?): Boolean {
        val spec = find(kernel) ?: return false
        return ExploitChoice.CVE_99491 in spec.routes
    }

    @JvmStatic
    fun supports98260(kernel: String?): Boolean {
        val spec = find(kernel) ?: return false
        return ExploitChoice.CVE_98260 in spec.routes
    }

    @JvmStatic
    fun recommendedFor(kernel: String?): ExploitChoice {
        return find(kernel)?.preferredRoute ?: ExploitChoice.CVE_98260
    }
}

class UiState {
    companion object {
        private const val MAX_LOG_ENTRIES = 250

        private fun readInitialKernel(): String {
            return try {
                Os.uname()?.release?.trim().orEmpty()
            } catch (_: Throwable) {
                System.getProperty("os.version")?.trim().orEmpty()
            }
        }

        private fun currentTimeString(): String {
            return SimpleDateFormat("HH:mm:ss", Locale.ROOT).format(Date())
        }
    }

    var statusTitle by mutableStateOf("等待 Shizuku")
    var statusDetail by mutableStateOf("先通过无线调试启动原版 Shizuku 服务")
    var statusTone by mutableStateOf(StatusTone.WARNING)
    var statusActive by mutableStateOf(false)

    var shizukuState by mutableStateOf("未连接")
    var shizukuReady by mutableStateOf(false)
    var shizukuTone by mutableStateOf(StatusTone.WARNING)

    var kernelState by mutableStateOf("待检查")
    var managerInstalled by mutableStateOf(false)
    var managerTone by mutableStateOf(StatusTone.IDLE)

    var currentKernel by mutableStateOf(readInitialKernel())
    var exploitChoice by mutableStateOf(ExploitChoice.AUTO)
    var progress by mutableFloatStateOf(4f)
    var logEntries by mutableStateOf<List<LogEntry>>(emptyList())
    var stages by mutableStateOf<List<StageProgress>>(emptyList())
    var busy by mutableStateOf(false)
    var rootReady by mutableStateOf(false)

    val model: String =
        Build.MODEL?.uppercase(Locale.ROOT) ?: "UNKNOWN"
    val device: String =
        Build.DEVICE?.uppercase(Locale.ROOT) ?: "UNKNOWN"

    val matchedKernel: SupportedKernelSpec?
        get() = SupportedKernels.find(currentKernel)

    val supports99491: Boolean
        get() = currentKernel.isBlank() || SupportedKernels.supports99491(currentKernel)

    val errorCount: Int
        get() = logEntries.count { it.isError }

    fun setStatus(title: String, detail: String, tone: StatusTone, active: Boolean) {
        statusTitle = title
        statusDetail = detail
        statusTone = tone
        statusActive = active
    }

    fun updateShizuku(label: String, ready: Boolean, tone: StatusTone) {
        shizukuState = label
        shizukuReady = ready
        shizukuTone = tone
    }

    fun updateManager(label: String, installed: Boolean, tone: StatusTone) {
        kernelState = label
        managerInstalled = installed
        managerTone = tone
    }

    fun updateKernel(kernel: String) {
        val trimmed = kernel.trim()
        if (trimmed.isEmpty()) return
        currentKernel = trimmed
        if (exploitChoice == ExploitChoice.CVE_99491 && !SupportedKernels.supports99491(trimmed)) {
            exploitChoice = ExploitChoice.AUTO
        }
    }

    fun appendLog(text: String, isError: Boolean) {
        val cleaned = text.trim()
        if (cleaned.isEmpty()) return
        val next = logEntries + LogEntry(
            timestamp = currentTimeString(),
            message = cleaned,
            isError = isError
        )
        logEntries = if (next.size > MAX_LOG_ENTRIES) {
            next.takeLast(MAX_LOG_ENTRIES)
        } else {
            next
        }
    }

    fun clearLogs() {
        logEntries = emptyList()
    }

    fun resetStages() {
        stages = emptyList()
    }

    fun startStage(title: String) {
        val now = System.currentTimeMillis()
        stages = stages.map {
            if (it.status == StageStatus.RUNNING)
                it.copy(
                    status = StageStatus.DONE,
                    durationMs = (now - it.startedAt).coerceAtLeast(0L)
                )
            else it
        } + StageProgress(title, StageStatus.RUNNING, 0L, now)
    }

    fun completeCurrentStage() {
        finishCurrentStage(StageStatus.DONE)
    }

    fun failCurrentStage() {
        finishCurrentStage(StageStatus.FAILED)
    }

    private fun finishCurrentStage(status: StageStatus) {
        val now = System.currentTimeMillis()
        stages = stages.map {
            if (it.status == StageStatus.RUNNING)
                it.copy(
                    status = status,
                    durationMs = (now - it.startedAt).coerceAtLeast(0L)
                )
            else it
        }
    }
}

interface UiActions {
    fun onConnectShizuku()
    fun onOpenKernelSu()
    fun onStartRoot()
    fun onSelectExploit(choice: ExploitChoice)
    fun onClearLogs()
}

object ComposeBridge {
    @JvmStatic
    fun attach(view: ComposeView, state: UiState, actions: UiActions) {
        view.setContent {
            LiquidGlassScreen(state = state, actions = actions)
        }
    }
}
