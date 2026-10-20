package com.aiden.honoroneclick

import android.os.Build
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.ComposeView
import java.util.Locale

class UiState {
    var statusTitle by mutableStateOf("等待 Shizuku")
    var statusDetail by mutableStateOf("先通过无线调试启动原版 Shizuku 服务")
    var shizukuState by mutableStateOf("未连接")
    var kernelState by mutableStateOf("待检查")
    var progress by mutableFloatStateOf(3f)
    var logs by mutableStateOf(
        "控制台已就绪。\nWKL-AN20 / WKL-AN80 白名单已启用。"
    )
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
}

interface UiActions {
    fun onConnectShizuku()
    fun onOpenKernelSu()
    fun onStartRoot()
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
