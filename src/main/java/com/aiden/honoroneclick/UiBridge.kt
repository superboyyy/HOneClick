package com.aiden.honoroneclick

import android.os.Build
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.ComposeView
import java.util.Locale

const val APP_VERSION_LABEL = "2.0 Beta 6"

enum class StageStatus {
    RUNNING,
    DONE,
    FAILED
}

data class StageProgress(
    val title: String,
    val status: StageStatus,
    val durationMs: Long,
    val startedAt: Long
)

enum class ExploitChoice(val label: String) {
    AUTO("自动"),
    LEGACY_64560("64560"),
    CVE_98260("98260")
}

class UiState {
    var statusTitle by mutableStateOf("等待 Shizuku")
    var statusDetail by mutableStateOf("先通过无线调试启动原版 Shizuku 服务")
    var shizukuState by mutableStateOf("未连接")
    var kernelState by mutableStateOf("待检查")
    var exploitChoice by mutableStateOf(ExploitChoice.AUTO)
    var legacyAllowed by mutableStateOf(true)
    var progress by mutableFloatStateOf(3f)
    var logs by mutableStateOf("")
    var stages by mutableStateOf<List<StageProgress>>(emptyList())
    var busy by mutableStateOf(false)
    var statusActive by mutableStateOf(false)

    val model: String =
        Build.MODEL?.uppercase(Locale.ROOT) ?: "UNKNOWN"
    val device: String =
        Build.DEVICE?.uppercase(Locale.ROOT) ?: "UNKNOWN"
    fun setStatus(title: String, detail: String, active: Boolean) {
        statusTitle = title
        statusDetail = detail
        statusActive = active
    }

    fun appendLog(text: String) {
        logs = if (logs.isBlank()) text else logs + "\n" + text
    }

    fun clearLogs() {
        logs = ""
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
    fun onImportBootImage()
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
