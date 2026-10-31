package com.aiden.honoroneclick

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.runtime.CompositionLocalProvider
import androidx.core.view.WindowCompat
import com.kyant.backdrop.backdrops.LayerBackdrop
import com.kyant.backdrop.backdrops.layerBackdrop
import com.kyant.backdrop.backdrops.rememberLayerBackdrop
import com.kyant.backdrop.drawBackdrop
import com.kyant.backdrop.effects.blur
import com.kyant.backdrop.effects.lens
import com.kyant.backdrop.effects.vibrancy
import android.content.res.Configuration

private val CardShape = RoundedCornerShape(28.dp)
private val CapsuleShape = RoundedCornerShape(50)

@Composable
fun LiquidGlassScreen(state: UiState, actions: UiActions) {
    val configuration = androidx.compose.ui.platform.LocalConfiguration.current
    val dark = configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK ==
            Configuration.UI_MODE_NIGHT_YES
    val background = if (dark) Color.Black else Color.White
    val foreground = if (dark) Color.White else Color.Black
    val muted = foreground.copy(alpha = 0.56f)
    val faint = foreground.copy(alpha = 0.10f)
    val backdrop = rememberLayerBackdrop()
    val view = LocalView.current

    SideEffect {
        val activity = view.context.findActivity() ?: return@SideEffect
        WindowCompat.getInsetsController(activity.window, view).apply {
            isAppearanceLightStatusBars = !dark
            isAppearanceLightNavigationBars = !dark
        }
    }

    Box(Modifier.fillMaxSize().background(background)) {
        BackgroundLayer(
            dark = dark,
            backdrop = backdrop,
            modifier = Modifier.fillMaxSize()
        )

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .windowInsetsPadding(WindowInsets.safeDrawing),
            contentPadding = PaddingValues(horizontal = 20.dp, vertical = 18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item { Header(foreground, muted) }
            item {
                StatusPanel(state, backdrop, foreground, muted, dark)
            }
            item {
                DevicePanel(state, actions, backdrop, foreground, muted, dark)
            }
            item {
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    MiniStatus(
                        "SHIZUKU",
                        state.shizukuState,
                        backdrop,
                        foreground,
                        muted,
                        dark,
                        Modifier.weight(1f)
                    )
                    MiniStatus(
                        "KERNELSU",
                        state.kernelState,
                        backdrop,
                        foreground,
                        muted,
                        dark,
                        Modifier.weight(1f)
                    )
                }
            }
            item {
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    GlassButton(
                        label = "01 连接 Shizuku",
                        primary = false,
                        backdrop = backdrop,
                        foreground = foreground,
                        dark = dark,
                        modifier = Modifier.weight(1f).height(52.dp)
                    ) { actions.onConnectShizuku() }
                    GlassButton(
                        label = "02 安装 KernelSU",
                        primary = false,
                        backdrop = backdrop,
                        foreground = foreground,
                        dark = dark,
                        modifier = Modifier.weight(1f).height(52.dp)
                    ) { actions.onOpenKernelSu() }
                }
            }
            item {
                GlassButton(
                    label = if (state.busy) "03 正在执行" else "03 开始提权",
                    enabled = !state.busy,
                    primary = true,
                    backdrop = backdrop,
                    foreground = foreground,
                    dark = dark,
                    modifier = Modifier.fillMaxWidth().height(60.dp)
                ) { actions.onStartRoot() }
            }
            if (state.stages.isNotEmpty()) {
                item {
                    StageProgressPanel(state, backdrop, foreground, muted, dark)
                }
            }
            item {
                LogPanel(state, actions, backdrop, foreground, muted, dark)
            }
            item {
                Footer(muted)
            }
        }
    }
}

@Composable
private fun Footer(
    muted: Color
) {
    val uriHandler = LocalUriHandler.current
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 10.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            "仅用于个人设备的安全研究",
            color = muted,
            fontSize = 11.sp,
            lineHeight = 18.sp,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth()
        )
        Text(
            "使用本应用可能存在风险，请自行评估并承担相应风险",
            color = muted,
            fontSize = 11.sp,
            lineHeight = 18.sp,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth()
        )
        Text(
            "请勿用于非法用途",
            color = muted,
            fontSize = 11.sp,
            lineHeight = 18.sp,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth()
        )
        Text(
            "https://github.com/superboyyy",
            color = Color(0xFF69D7A7),
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 6.dp)
                .clickable(role = Role.Button) {
                    uriHandler.openUri("https://github.com/superboyyy")
                }
        )
        Text(
            "HOneClick · " + APP_VERSION_LABEL,
            color = muted,
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp)
        )
    }
}

@Composable
private fun BackgroundLayer(
    dark: Boolean,
    backdrop: LayerBackdrop,
    modifier: Modifier
) {
    val color = if (dark) Color.White else Color.Black
    Box(
        modifier
            .background(if (dark) Color.Black else Color.White)
            .layerBackdrop(backdrop)
    ) {
        Text(
            text = "ANY",
            color = color.copy(alpha = 0.045f),
            fontSize = 176.sp,
            fontWeight = FontWeight.Black,
            letterSpacing = (-8).sp,
            modifier = Modifier
                .align(Alignment.TopEnd)
                .offset(x = 34.dp, y = 54.dp)
        )
        Text(
            text = "ONE\nCLICK",
            color = color.copy(alpha = 0.028f),
            fontSize = 74.sp,
            lineHeight = 68.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier
                .align(Alignment.BottomStart)
                .offset(x = 18.dp, y = 22.dp)
        )
    }
}

@Composable
private fun Header(foreground: Color, muted: Color) {
    Row(
        Modifier.fillMaxWidth().padding(top = 14.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier
                .size(58.dp)
                .background(foreground.copy(alpha = 0.055f), RoundedCornerShape(20.dp))
                .border(1.dp, foreground.copy(alpha = 0.14f), RoundedCornerShape(20.dp))
                .padding(7.dp)
        ) {
            Image(
                painter = painterResource(R.drawable.ic_launcher_foreground),
                contentDescription = null,
                modifier = Modifier.fillMaxSize()
            )
        }
        Text(
            "HOneClick",
            color = foreground,
            fontSize = 34.sp,
            lineHeight = 34.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = (-1.2).sp,
            modifier = Modifier.padding(start = 15.dp)
        )
    }
    Text(
        "酷安 @熠寻",
        color = muted,
        fontSize = 13.sp,
        letterSpacing = 0.3.sp,
        textAlign = TextAlign.Center,
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 2.dp, bottom = 8.dp)
    )
}

@Composable
private fun StatusPanel(
    state: UiState,
    backdrop: LayerBackdrop,
    foreground: Color,
    muted: Color,
    dark: Boolean
) {
    GlassCard(backdrop, foreground, dark) {
        Eyebrow("系统状态", muted)
        Spacer(Modifier.height(10.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier
                    .size(10.dp)
                    .background(
                        if (state.statusActive) foreground
                        else foreground.copy(alpha = 0.22f),
                        CircleShape
                    )
                    .border(
                        1.dp,
                        foreground.copy(alpha = if (state.statusActive) 0f else 0.55f),
                        CircleShape
                    )
            )
            Spacer(Modifier.width(10.dp))
            Text(
                state.statusTitle,
                color = foreground,
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold
            )
        }
        Text(
            state.statusDetail,
            color = muted,
            fontSize = 13.sp,
            modifier = Modifier.padding(top = 5.dp, bottom = 15.dp)
        )
        LiquidProgress(state.progress, foreground)
    }
}

@Composable
private fun DevicePanel(
    state: UiState,
    actions: UiActions,
    backdrop: LayerBackdrop,
    foreground: Color,
    muted: Color,
    dark: Boolean
) {
    GlassCard(backdrop, foreground, dark) {
        Eyebrow("设备信息", muted)
        Text(
            state.model,
            color = foreground,
            fontSize = 26.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(top = 7.dp)
        )
        Spacer(Modifier.height(18.dp))
        Eyebrow("漏洞利用", muted)
        Row(
            Modifier.fillMaxWidth().padding(top = 9.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            ExploitChoice.entries.forEach { choice ->
                RouteChip(
                    choice = choice,
                    selected = state.exploitChoice == choice,
                    enabled = !state.busy &&
                        (choice != ExploitChoice.LEGACY_64560 || state.legacyAllowed),
                    foreground = foreground,
                    muted = muted,
                    dark = dark,
                    modifier = Modifier.weight(1f)
                ) { actions.onSelectExploit(choice) }
            }
        }
        GlassButton(
            label = "导入 boot.img 生成配置",
            primary = false,
            backdrop = backdrop,
            foreground = foreground,
            dark = dark,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 12.dp)
                .height(48.dp)
        ) { actions.onImportBootImage() }
        Text(
            "若提权失败且当前内核不是 6.18.21-android17 版本，请尝试导入 boot.img 进行提权。",
            color = muted,
            fontSize = 11.sp,
            lineHeight = 17.sp,
            modifier = Modifier.padding(top = 8.dp)
        )
    }
}

@Composable
private fun RouteChip(
    choice: ExploitChoice,
    selected: Boolean,
    enabled: Boolean,
    foreground: Color,
    muted: Color,
    dark: Boolean,
    modifier: Modifier,
    onClick: () -> Unit
) {
    Box(
        modifier
            .height(38.dp)
            .clip(CapsuleShape)
            .background(foreground.copy(alpha = if (selected) 0.92f else 0.055f))
            .border(
                1.dp,
                foreground.copy(alpha = if (selected) 0f else 0.16f),
                CapsuleShape
            )
            .selectable(
                selected = selected,
                enabled = enabled,
                role = Role.RadioButton,
                onClick = onClick
            ),
        contentAlignment = Alignment.Center
    ) {
        Text(
            choice.label,
            color = if (selected) { if (dark) Color.Black else Color.White } else muted,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center
        )
    }
}

@Composable
private fun MiniStatus(
    label: String,
    value: String,
    backdrop: LayerBackdrop,
    foreground: Color,
    muted: Color,
    dark: Boolean,
    modifier: Modifier
) {
    GlassCard(backdrop, foreground, dark, modifier) {
        Eyebrow(label, muted)
        Text(
            value,
            color = foreground,
            fontSize = 16.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(top = 7.dp)
        )
    }
}

@Composable
private fun GlassCard(
    backdrop: LayerBackdrop,
    foreground: Color,
    dark: Boolean,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(
        modifier
            .fillMaxWidth()
            .liquidGlass(backdrop, foreground, dark, CardShape)
            .padding(18.dp),
        content = content
    )
}

@Composable
private fun GlassButton(
    label: String,
    primary: Boolean,
    backdrop: LayerBackdrop,
    foreground: Color,
    dark: Boolean,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    onClick: () -> Unit
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val alpha = when {
        !enabled -> 0.35f
        pressed -> 0.52f
        primary -> 0.20f
        else -> 0.075f
    }
    Box(
        modifier
            .graphicsLayer {
                scaleX = if (pressed && enabled) 0.985f else 1f
                scaleY = if (pressed && enabled) 0.985f else 1f
            }
            .drawBackdrop(
                backdrop = backdrop,
                shape = { CapsuleShape },
                effects = {
                    vibrancy()
                    blur(14.dp.toPx())
                    lens(16.dp.toPx(), 28.dp.toPx(), chromaticAberration = true)
                },
                onDrawSurface = {
                    drawRect(foreground.copy(alpha = alpha))
                }
            )
            .border(
                if (primary) 1.5.dp else 1.dp,
                foreground.copy(alpha = if (primary) 0.62f else 0.23f),
                CapsuleShape
            )
            .clip(CapsuleShape)
            .clickable(
                interactionSource = interaction,
                indication = null,
                enabled = enabled,
                role = Role.Button,
                onClick = onClick
            ),
        contentAlignment = Alignment.Center
    ) {
        Text(
            label,
            color = foreground,
            fontSize = if (primary) 17.sp else 15.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 0.2.sp
        )
    }
}


@Composable
private fun StageProgressPanel(
    state: UiState,
    backdrop: LayerBackdrop,
    foreground: Color,
    muted: Color,
    dark: Boolean
) {
    val total = state.stages.sumOf { it.durationMs }
    GlassCard(backdrop, foreground, dark) {
        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Eyebrow("进度", muted, Modifier.weight(1f))
            Text(
                formatDuration(total),
                color = muted,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp
            )
        }
        Column(Modifier.fillMaxWidth().padding(top = 14.dp)) {
            state.stages.forEachIndexed { index, stage ->
                val errorColor = Color(0xFFFF7B72)
                val statusColor = when (stage.status) {
                    StageStatus.FAILED -> errorColor
                    StageStatus.RUNNING -> foreground
                    StageStatus.DONE -> muted
                }
                Row(
                    Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        Modifier
                            .size(27.dp)
                            .background(
                                if (stage.status == StageStatus.FAILED)
                                    errorColor.copy(alpha = 0.16f)
                                else foreground.copy(alpha = 0.07f),
                                CircleShape
                            )
                            .border(
                                1.dp,
                                statusColor.copy(alpha = 0.35f),
                                CircleShape
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            "${index + 1}",
                            color = statusColor,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Text(
                        stage.title,
                        color = if (stage.status == StageStatus.DONE) muted else foreground,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.weight(1f).padding(start = 12.dp)
                    )
                    Text(
                        when (stage.status) {
                            StageStatus.RUNNING -> "进行中"
                            StageStatus.DONE -> formatDuration(stage.durationMs)
                            StageStatus.FAILED -> "失败 · " + formatDuration(stage.durationMs)
                        },
                        color = statusColor,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp
                    )
                }
                if (index != state.stages.lastIndex) {
                    Box(
                        Modifier.width(27.dp).height(28.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            "↓",
                            color = muted.copy(alpha = 0.7f),
                            fontSize = 18.sp
                        )
                    }
                }
            }
        }
    }
}

private fun formatDuration(ms: Long): String {
    val tenths = ((ms.coerceAtLeast(0L) + 50L) / 100L)
    val seconds = tenths / 10L
    return if (seconds < 60L) {
        "$seconds.${tenths % 10L}s"
    } else {
        "${seconds / 60L}m ${seconds % 60L}s"
    }
}

@Composable
private fun LogPanel(
    state: UiState,
    actions: UiActions,
    backdrop: LayerBackdrop,
    foreground: Color,
    muted: Color,
    dark: Boolean
) {
    val scroll = rememberScrollState()
    LaunchedEffect(state.logs) {
        scroll.animateScrollTo(scroll.maxValue)
    }
    GlassCard(backdrop, foreground, dark) {
        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Eyebrow("错误日志", muted, Modifier.weight(1f))
            Text(
                "清空",
                color = foreground,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier
                    .clip(CapsuleShape)
                    .clickable(role = Role.Button, onClick = actions::onClearLogs)
                    .padding(horizontal = 9.dp, vertical = 5.dp)
            )
        }
        SelectionContainer {
            Text(
                text = state.logs.ifBlank { "暂无错误" },
                color = if (state.logs.isBlank()) muted else Color(0xFFFF8A80),
                fontFamily = FontFamily.Monospace,
                fontSize = 11.5.sp,
                lineHeight = 18.sp,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(if (state.logs.isBlank()) 56.dp else 112.dp)
                    .padding(top = 11.dp)
                    .verticalScroll(scroll)
            )
        }
    }
}

@Composable
private fun LiquidProgress(progress: Float, color: Color) {
    Box(
        Modifier
            .fillMaxWidth()
            .height(8.dp)
            .clip(CapsuleShape)
            .background(color.copy(alpha = 0.075f))
    ) {
        Box(
            Modifier
                .fillMaxWidth(progress.coerceIn(0f, 100f) / 100f)
                .height(8.dp)
                .clip(CapsuleShape)
                .background(color.copy(alpha = 0.88f))
        )
    }
}

@Composable
private fun Eyebrow(
    text: String,
    color: Color,
    modifier: Modifier = Modifier
) {
    Text(
        text,
        color = color,
        fontSize = 10.sp,
        fontWeight = FontWeight.Bold,
        letterSpacing = 1.6.sp,
        modifier = modifier
    )
}

@Composable
private fun Text(
    text: String,
    color: Color,
    modifier: Modifier = Modifier,
    fontSize: androidx.compose.ui.unit.TextUnit =
        androidx.compose.ui.unit.TextUnit.Unspecified,
    fontWeight: FontWeight? = null,
    fontFamily: FontFamily? = null,
    letterSpacing: androidx.compose.ui.unit.TextUnit =
        androidx.compose.ui.unit.TextUnit.Unspecified,
    lineHeight: androidx.compose.ui.unit.TextUnit =
        androidx.compose.ui.unit.TextUnit.Unspecified,
    textAlign: TextAlign? = null
) {
    BasicText(
        text = text,
        modifier = modifier,
        style = TextStyle(
            color = color,
            fontSize = fontSize,
            fontWeight = fontWeight,
            fontFamily = fontFamily,
            letterSpacing = letterSpacing,
            lineHeight = lineHeight,
            textAlign = textAlign ?: TextAlign.Unspecified
        )
    )
}

private fun Modifier.liquidGlass(
    backdrop: LayerBackdrop,
    foreground: Color,
    dark: Boolean,
    shape: RoundedCornerShape
): Modifier =
    drawBackdrop(
        backdrop = backdrop,
        shape = { shape },
        effects = {
            vibrancy()
            blur(18.dp.toPx())
            lens(18.dp.toPx(), 34.dp.toPx(), chromaticAberration = true)
        },
        onDrawSurface = {
            drawRect(
                if (dark) Color.White.copy(alpha = 0.065f)
                else Color.Black.copy(alpha = 0.04f)
            )
        }
    )
        .border(
            1.dp,
            foreground.copy(alpha = 0.16f),
            shape
        )
        .clip(shape)

private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}
