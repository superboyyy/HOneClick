package com.aiden.honoroneclick

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.ContextWrapper
import android.content.res.Configuration
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.Canvas
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
import androidx.compose.foundation.layout.heightIn
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
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat
import com.kyant.backdrop.backdrops.LayerBackdrop
import com.kyant.backdrop.backdrops.layerBackdrop
import com.kyant.backdrop.backdrops.rememberLayerBackdrop
import com.kyant.backdrop.drawBackdrop
import com.kyant.backdrop.effects.blur
import com.kyant.backdrop.effects.lens
import com.kyant.backdrop.effects.vibrancy
import kotlinx.coroutines.delay

private val CardShape = RoundedCornerShape(26.dp)
private val InnerShape = RoundedCornerShape(16.dp)
private val CapsuleShape = RoundedCornerShape(50)

private data class GlassPalette(
    val dark: Boolean,
    val background: Color,
    val foreground: Color,
    val muted: Color,
    val subtle: Color,
    val cardFill: Color,
    val innerFill: Color,
    val innerBorder: Color,
    val positive: Color,
    val warning: Color,
    val running: Color,
    val danger: Color,
    val link: Color
) {
    fun colorFor(tone: StatusTone): Color = when (tone) {
        StatusTone.IDLE -> muted
        StatusTone.WARNING -> warning
        StatusTone.READY -> positive
        StatusTone.RUNNING -> running
        StatusTone.SUCCESS -> positive
        StatusTone.ERROR -> danger
    }

    fun borderBrush(elevated: Boolean = false): Brush {
        val top = if (dark) {
            Color.White.copy(alpha = if (elevated) 0.24f else 0.18f)
        } else {
            Color.Black.copy(alpha = if (elevated) 0.16f else 0.12f)
        }
        val mid = if (dark) {
            Color.White.copy(alpha = 0.10f)
        } else {
            Color.Black.copy(alpha = 0.08f)
        }
        val bottom = if (dark) {
            Color.White.copy(alpha = 0.06f)
        } else {
            Color.Black.copy(alpha = 0.11f)
        }
        return Brush.verticalGradient(listOf(top, mid, bottom))
    }
}

private fun glassPalette(dark: Boolean): GlassPalette = if (dark) {
    GlassPalette(
        dark = true,
        background = Color.Black,
        foreground = Color.White,
        muted = Color.White.copy(alpha = 0.56f),
        subtle = Color.White.copy(alpha = 0.36f),
        cardFill = Color.White.copy(alpha = 0.065f),
        innerFill = Color.White.copy(alpha = 0.050f),
        innerBorder = Color.White.copy(alpha = 0.10f),
        positive = Color(0xFF4ADE9F),
        warning = Color(0xFFF5B95B),
        running = Color(0xFF60C6FF),
        danger = Color(0xFFFF7B72),
        link = Color(0xFF64D6A8)
    )
} else {
    GlassPalette(
        dark = false,
        background = Color.White,
        foreground = Color.Black,
        muted = Color.Black.copy(alpha = 0.56f),
        subtle = Color.Black.copy(alpha = 0.36f),
        cardFill = Color.Black.copy(alpha = 0.040f),
        innerFill = Color.Black.copy(alpha = 0.038f),
        innerBorder = Color.Black.copy(alpha = 0.085f),
        positive = Color(0xFF0D9668),
        warning = Color(0xFFC2780A),
        running = Color(0xFF0277BD),
        danger = Color(0xFFD32F2F),
        link = Color(0xFF0D8A60)
    )
}

@Composable
fun LiquidGlassScreen(state: UiState, actions: UiActions) {
    val configuration = LocalConfiguration.current
    val dark = configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK ==
        Configuration.UI_MODE_NIGHT_YES
    val palette = remember(dark) { glassPalette(dark) }
    val backdrop = rememberLayerBackdrop()
    val view = LocalView.current

    SideEffect {
        val activity = view.context.findActivity() ?: return@SideEffect
        WindowCompat.getInsetsController(activity.window, view).apply {
            isAppearanceLightStatusBars = !dark
            isAppearanceLightNavigationBars = !dark
        }
    }

    val hasRunningStage = state.stages.any { it.status == StageStatus.RUNNING }
    var liveNowMs by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(hasRunningStage, state.busy) {
        if (hasRunningStage || state.busy) {
            while (true) {
                liveNowMs = System.currentTimeMillis()
                delay(250L)
            }
        }
    }

    val totalElapsedMs = remember(state.stages, liveNowMs) {
        state.stages.sumOf { stage ->
            if (stage.status == StageStatus.RUNNING) {
                (liveNowMs - stage.startedAt).coerceAtLeast(0L)
            } else {
                stage.durationMs
            }
        }
    }

    Box(Modifier.fillMaxSize().background(palette.background)) {
        BackgroundLayer(
            palette = palette,
            backdrop = backdrop,
            modifier = Modifier.fillMaxSize()
        )

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .windowInsetsPadding(WindowInsets.safeDrawing),
            contentPadding = PaddingValues(horizontal = 18.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item(key = "header") {
                Header(palette)
            }
            item(key = "device") {
                DevicePanel(
                    state = state,
                    actions = actions,
                    backdrop = backdrop,
                    palette = palette
                )
            }
            item(key = "status") {
                StatusPanel(
                    state = state,
                    totalElapsedMs = totalElapsedMs,
                    backdrop = backdrop,
                    palette = palette
                )
            }
            item(key = "steps") {
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    StepActionCard(
                        step = "01",
                        title = "SHIZUKU",
                        value = state.shizukuState,
                        actionHint = when {
                            state.shizukuReady -> "已就绪 · 点此刷新"
                            state.shizukuTone == StatusTone.WARNING && state.shizukuState == "待授权" -> "点击授予权限 ›"
                            else -> "启动或安装 ›"
                        },
                        tone = state.shizukuTone,
                        completed = state.shizukuReady,
                        enabled = !state.busy,
                        backdrop = backdrop,
                        palette = palette,
                        modifier = Modifier.weight(1f),
                        onClick = actions::onConnectShizuku
                    )
                    StepActionCard(
                        step = "02",
                        title = BuildConfig.ROOT_MANAGER_NAME.uppercase(),
                        value = state.kernelState,
                        actionHint = if (state.managerInstalled || state.rootReady) {
                            "打开管理器 ›"
                        } else {
                            "安装管理器 ›"
                        },
                        tone = state.managerTone,
                        completed = state.managerInstalled || state.rootReady,
                        enabled = !state.busy,
                        backdrop = backdrop,
                        palette = palette,
                        modifier = Modifier.weight(1f),
                        onClick = actions::onOpenKernelSu
                    )
                }
            }
            item(key = "primary_action") {
                PrimaryActionButton(
                    state = state,
                    backdrop = backdrop,
                    palette = palette,
                    onClick = actions::onStartRoot
                )
            }
            if (state.stages.isNotEmpty()) {
                item(key = "stages") {
                    StageProgressPanel(
                        stages = state.stages,
                        liveNowMs = liveNowMs,
                        totalElapsedMs = totalElapsedMs,
                        backdrop = backdrop,
                        palette = palette
                    )
                }
            }
            item(key = "logs") {
                LogPanel(
                    state = state,
                    actions = actions,
                    backdrop = backdrop,
                    palette = palette
                )
            }
            item(key = "footer") {
                Footer(palette)
            }
        }
    }
}

@Composable
private fun BackgroundLayer(
    palette: GlassPalette,
    backdrop: LayerBackdrop,
    modifier: Modifier
) {
    Box(
        modifier
            .background(palette.background)
            .layerBackdrop(backdrop)
    )
}

@Composable
private fun Header(palette: GlassPalette) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(top = 6.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier
                .size(52.dp)
                .clip(RoundedCornerShape(17.dp))
                .background(palette.innerFill)
                .border(1.dp, palette.borderBrush(), RoundedCornerShape(17.dp))
                .padding(6.dp)
        ) {
            Image(
                painter = painterResource(R.drawable.ic_launcher_foreground),
                contentDescription = null,
                modifier = Modifier.fillMaxSize()
            )
        }
        Spacer(Modifier.width(13.dp))
        Column(Modifier.weight(1f)) {
            Text(
                text = "HOneClick",
                color = palette.foreground,
                fontSize = 28.sp,
                lineHeight = 30.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = (-0.9).sp,
                maxLines = 1
            )
            Text(
                text = "酷安 @熠寻",
                color = palette.muted,
                fontSize = 12.sp,
                letterSpacing = 0.2.sp,
                modifier = Modifier.padding(top = 3.dp)
            )
        }
    }
}

@Composable
private fun StatusPanel(
    state: UiState,
    totalElapsedMs: Long,
    backdrop: LayerBackdrop,
    palette: GlassPalette
) {
    val accent = palette.colorFor(state.statusTone)
    val badgeText = when {
        state.busy -> "执行中 · ${formatDuration(totalElapsedMs)}"
        state.rootReady -> "已提权"
        state.statusTone == StatusTone.ERROR -> "未完成"
        state.statusTone == StatusTone.READY -> "已就绪"
        state.shizukuState == "待授权" -> "待授权"
        else -> "待连接"
    }

    GlassCard(
        backdrop = backdrop,
        palette = palette,
        elevated = true
    ) {
        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Eyebrow("系统状态", palette.muted, Modifier.weight(1f))
            StatusBadge(
                label = badgeText,
                color = accent,
                pulsing = state.busy,
                palette = palette
            )
        }

        Spacer(Modifier.height(10.dp))

        Text(
            text = state.statusTitle,
            color = palette.foreground,
            fontSize = 23.sp,
            lineHeight = 28.sp,
            fontWeight = FontWeight.Bold
        )
        Text(
            text = state.statusDetail,
            color = palette.muted,
            fontSize = 13.sp,
            lineHeight = 19.sp,
            modifier = Modifier.padding(top = 4.dp)
        )

        AnimatedVisibility(
            visible = state.busy,
            enter = fadeIn() + expandVertically(),
            exit = fadeOut() + shrinkVertically()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 10.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(palette.innerFill)
                    .border(1.dp, palette.innerBorder, RoundedCornerShape(12.dp))
                    .padding(horizontal = 11.dp, vertical = 7.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    Modifier
                        .size(6.dp)
                        .clip(CircleShape)
                        .background(palette.running)
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = "屏幕已保持常亮 · 完整流程可能需要 10–30 分钟",
                    color = palette.foreground.copy(alpha = 0.88f),
                    fontSize = 11.5.sp,
                    lineHeight = 16.sp
                )
            }
        }

        Spacer(Modifier.height(14.dp))
        LiquidProgress(
            progress = state.progress,
            accent = accent,
            busy = state.busy,
            palette = palette
        )
    }
}

@Composable
private fun StatusBadge(
    label: String,
    color: Color,
    pulsing: Boolean,
    palette: GlassPalette
) {
    val pulseTransition = rememberInfiniteTransition(label = "dotPulse")
    val pulseAlpha by pulseTransition.animateFloat(
        initialValue = 0.28f,
        targetValue = 0.90f,
        animationSpec = infiniteRepeatable(
            animation = tween(850, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseAlpha"
    )
    Row(
        modifier = Modifier
            .clip(CapsuleShape)
            .background(color.copy(alpha = if (palette.dark) 0.14f else 0.10f))
            .border(1.dp, color.copy(alpha = if (palette.dark) 0.30f else 0.24f), CapsuleShape)
            .padding(horizontal = 9.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier
                .size(7.dp)
                .clip(CircleShape)
                .background(color.copy(alpha = if (pulsing) pulseAlpha else 1f))
        )
        Spacer(Modifier.width(6.dp))
        Text(
            text = label,
            color = color,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace,
            maxLines = 1
        )
    }
}

@Composable
private fun StepActionCard(
    step: String,
    title: String,
    value: String,
    actionHint: String,
    tone: StatusTone,
    completed: Boolean,
    enabled: Boolean,
    backdrop: LayerBackdrop,
    palette: GlassPalette,
    modifier: Modifier,
    onClick: () -> Unit
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val scale by animateFloatAsState(
        targetValue = if (pressed && enabled) 0.975f else 1f,
        animationSpec = tween(120),
        label = "stepScale"
    )
    val accent = palette.colorFor(tone)

    Column(
        modifier = modifier
            .graphicsLayer {
                scaleX = scale
                scaleY = scale
            }
            .alpha(if (enabled) 1f else 0.58f)
            .liquidGlass(
                backdrop = backdrop,
                palette = palette,
                shape = CardShape,
                elevated = false
            )
            .clickable(
                interactionSource = interaction,
                indication = null,
                enabled = enabled,
                role = Role.Button,
                onClick = onClick
            )
            .padding(horizontal = 15.dp, vertical = 14.dp)
    ) {
        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = step,
                color = if (completed) palette.positive else palette.muted,
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier
                    .clip(CapsuleShape)
                    .background(
                        if (completed) palette.positive.copy(alpha = if (palette.dark) 0.16f else 0.12f)
                        else palette.innerFill
                    )
                    .padding(horizontal = 6.dp, vertical = 2.dp)
            )
            Spacer(Modifier.width(6.dp))
            Text(
                text = title,
                color = palette.muted,
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.1.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f)
            )
            if (completed) {
                CheckIcon(
                    color = palette.positive,
                    modifier = Modifier.size(14.dp)
                )
            } else {
                Box(
                    Modifier
                        .size(7.dp)
                        .clip(CircleShape)
                        .background(accent.copy(alpha = 0.85f))
                )
            }
        }

        Spacer(Modifier.height(9.dp))

        Text(
            text = value,
            color = if (tone == StatusTone.IDLE) palette.foreground else accent,
            fontSize = 16.sp,
            fontWeight = FontWeight.Bold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            text = actionHint,
            color = palette.muted,
            fontSize = 11.5.sp,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(top = 4.dp)
        )
    }
}

@Composable
private fun PrimaryActionButton(
    state: UiState,
    backdrop: LayerBackdrop,
    palette: GlassPalette,
    onClick: () -> Unit
) {
    val enabled = !state.busy
    val ready = state.shizukuReady
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val scale by animateFloatAsState(
        targetValue = if (pressed && enabled) 0.98f else 1f,
        animationSpec = tween(120),
        label = "ctaScale"
    )

    val surfaceAlpha = when {
        state.busy -> if (palette.dark) 0.08f else 0.05f
        pressed && enabled -> if (palette.dark) 0.24f else 0.16f
        ready -> if (palette.dark) 0.15f else 0.09f
        else -> if (palette.dark) 0.065f else 0.045f
    }
    val borderColor = when {
        state.busy -> palette.foreground.copy(alpha = 0.22f)
        ready -> palette.foreground.copy(alpha = if (palette.dark) 0.48f else 0.32f)
        else -> palette.foreground.copy(alpha = 0.16f)
    }
    val label = when {
        state.busy -> "03 正在执行提权…"
        state.rootReady -> "03 Root 已就绪 · 重新验收"
        ready -> "03 开始提权"
        else -> "03 开始提权（需先完成 01）"
    }
    val textColor = when {
        state.busy -> palette.foreground.copy(alpha = 0.64f)
        ready -> palette.foreground
        else -> palette.muted
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(58.dp)
            .graphicsLayer {
                scaleX = scale
                scaleY = scale
            }
            .drawBackdrop(
                backdrop = backdrop,
                shape = { CapsuleShape },
                effects = {
                    vibrancy()
                    blur(16.dp.toPx())
                    lens(14.dp.toPx(), 26.dp.toPx(), chromaticAberration = false)
                },
                onDrawSurface = {
                    drawRect(palette.foreground.copy(alpha = surfaceAlpha))
                }
            )
            .border(
                width = if (ready || state.busy) 1.5.dp else 1.dp,
                color = borderColor,
                shape = CapsuleShape
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
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center,
            modifier = Modifier.padding(horizontal = 18.dp)
        ) {
            if (state.busy) {
                RunningSpinner(
                    color = palette.running,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(Modifier.width(10.dp))
            } else if (state.rootReady) {
                CheckIcon(
                    color = palette.positive,
                    modifier = Modifier.size(17.dp)
                )
                Spacer(Modifier.width(8.dp))
            }
            Text(
                text = label,
                color = textColor,
                fontSize = 16.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 0.2.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun StageProgressPanel(
    stages: List<StageProgress>,
    liveNowMs: Long,
    totalElapsedMs: Long,
    backdrop: LayerBackdrop,
    palette: GlassPalette
) {
    val pulseTransition = rememberInfiniteTransition(label = "stagePulse")
    val pulseAlpha by pulseTransition.animateFloat(
        initialValue = 0.25f,
        targetValue = 0.85f,
        animationSpec = infiniteRepeatable(
            animation = tween(900, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "stageRingAlpha"
    )

    GlassCard(
        backdrop = backdrop,
        palette = palette
    ) {
        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Eyebrow("执行进度", palette.muted, Modifier.weight(1f))
            Text(
                text = formatDuration(totalElapsedMs),
                color = palette.muted,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.5.sp,
                fontWeight = FontWeight.SemiBold
            )
        }

        Column(Modifier.fillMaxWidth().padding(top = 14.dp)) {
            stages.forEachIndexed { index, stage ->
                val isLast = index == stages.lastIndex
                val stepColor = when (stage.status) {
                    StageStatus.DONE -> palette.positive
                    StageStatus.RUNNING -> palette.running
                    StageStatus.FAILED -> palette.danger
                }
                val durationMs = if (stage.status == StageStatus.RUNNING) {
                    (liveNowMs - stage.startedAt).coerceAtLeast(0L)
                } else {
                    stage.durationMs
                }

                Row(
                    Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        Modifier
                            .size(26.dp)
                            .clip(CircleShape)
                            .background(
                                stepColor.copy(
                                    alpha = when (stage.status) {
                                        StageStatus.RUNNING -> if (palette.dark) 0.20f else 0.14f
                                        else -> if (palette.dark) 0.14f else 0.10f
                                    }
                                )
                            )
                            .border(
                                width = if (stage.status == StageStatus.RUNNING) 1.5.dp else 1.dp,
                                color = stepColor.copy(
                                    alpha = if (stage.status == StageStatus.RUNNING) pulseAlpha else 0.42f
                                ),
                                shape = CircleShape
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        when (stage.status) {
                            StageStatus.DONE -> CheckIcon(
                                color = stepColor,
                                modifier = Modifier.size(13.dp)
                            )
                            StageStatus.FAILED -> CrossIcon(
                                color = stepColor,
                                modifier = Modifier.size(11.dp)
                            )
                            StageStatus.RUNNING -> Text(
                                text = "${index + 1}",
                                color = stepColor,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }

                    Text(
                        text = stage.title,
                        color = if (stage.status == StageStatus.DONE) palette.muted else palette.foreground,
                        fontSize = 13.5.sp,
                        fontWeight = if (stage.status == StageStatus.DONE) FontWeight.Medium else FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier
                            .weight(1f)
                            .padding(horizontal = 11.dp)
                    )

                    Text(
                        text = when (stage.status) {
                            StageStatus.RUNNING -> "进行中 · ${formatDuration(durationMs)}"
                            StageStatus.DONE -> formatDuration(durationMs)
                            StageStatus.FAILED -> "失败 · ${formatDuration(durationMs)}"
                        },
                        color = if (stage.status == StageStatus.DONE) palette.muted else stepColor,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        fontWeight = if (stage.status == StageStatus.DONE) FontWeight.Normal else FontWeight.SemiBold,
                        maxLines = 1
                    )
                }

                if (!isLast) {
                    Box(
                        modifier = Modifier
                            .width(26.dp)
                            .height(18.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Box(
                            Modifier
                                .width(1.5.dp)
                                .height(14.dp)
                                .clip(CapsuleShape)
                                .background(
                                    if (stage.status == StageStatus.DONE) {
                                        palette.positive.copy(alpha = 0.35f)
                                    } else {
                                        palette.innerBorder
                                    }
                                )
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun DevicePanel(
    state: UiState,
    actions: UiActions,
    backdrop: LayerBackdrop,
    palette: GlassPalette
) {
    val context = LocalContext.current
    val matched = state.matchedKernel
    val hasKernel = state.currentKernel.isNotBlank()
    var kernelsExpanded by remember(matched == null && hasKernel) {
        mutableStateOf(hasKernel && matched == null)
    }

    val matchBadgeText = when {
        matched != null -> "内核已支持"
        hasKernel -> "未验证内核"
        else -> "待检测"
    }
    val matchBadgeColor = when {
        matched != null -> palette.positive
        hasKernel -> palette.warning
        else -> palette.muted
    }

    val routeSummary = when (state.exploitChoice) {
        ExploitChoice.AUTO -> when {
            matched != null -> "自动模式：已匹配当前内核，将优先使用 ${matched.preferredRoute.label}。"
            hasKernel -> "自动模式：当前内核不在内置列表中，将尝试默认利用链。"
            else -> "自动模式：连接 Shizuku 后按实际内核选择利用链。"
        }
        ExploitChoice.CVE_99491 -> "已手动指定 99491 利用链。"
        ExploitChoice.CVE_98260 -> "已手动指定 98260 利用链。"
    }

    GlassCard(
        backdrop = backdrop,
        palette = palette
    ) {
        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Eyebrow("设备与利用链", palette.muted, Modifier.weight(1f))
            StatusBadge(
                label = matchBadgeText,
                color = matchBadgeColor,
                pulsing = false,
                palette = palette
            )
        }

        Row(
            modifier = Modifier.padding(top = 8.dp),
            verticalAlignment = Alignment.Bottom,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = state.model,
                color = palette.foreground,
                fontSize = 22.sp,
                fontWeight = FontWeight.Bold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            if (state.device.isNotBlank() && state.device != state.model) {
                Text(
                    text = state.device,
                    color = palette.muted,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 1,
                    modifier = Modifier.padding(bottom = 3.dp)
                )
            }
        }

        // Current device kernel readout
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 10.dp)
                .clip(InnerShape)
                .background(palette.innerFill)
                .border(1.dp, palette.innerBorder, InnerShape)
                .clickable(enabled = hasKernel, role = Role.Button) {
                    copyToClipboard(context, "kernel", state.currentKernel)
                    Toast.makeText(context, "已复制当前内核版本", Toast.LENGTH_SHORT).show()
                }
                .padding(horizontal = 12.dp, vertical = 10.dp)
        ) {
            Row(
                Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "当前内核",
                    color = palette.muted,
                    fontSize = 10.5.sp,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f)
                )
                if (hasKernel) {
                    Text(
                        text = "点按复制",
                        color = palette.subtle,
                        fontSize = 10.5.sp
                    )
                }
            }
            Text(
                text = state.currentKernel.ifBlank { "等待读取 uname -r" },
                color = palette.foreground,
                fontSize = 11.sp,
                lineHeight = 16.sp,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier.padding(top = 4.dp)
            )
            if (matched != null) {
                Row(
                    modifier = Modifier.padding(top = 7.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "可用链",
                        color = palette.muted,
                        fontSize = 10.5.sp
                    )
                    matched.routes.forEach { route ->
                        KernelTag(
                            label = if (route == matched.preferredRoute && matched.routes.size > 1) {
                                "${route.label} · 推荐"
                            } else {
                                route.label
                            },
                            highlighted = route == matched.preferredRoute,
                            accent = palette.positive,
                            palette = palette
                        )
                    }
                }
            }
        }

        Spacer(Modifier.height(14.dp))
        Eyebrow("漏洞利用", palette.muted)
        Row(
            Modifier.fillMaxWidth().padding(top = 9.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            ExploitChoice.entries.forEach { choice ->
                val compatible = choice != ExploitChoice.CVE_99491 || state.supports99491
                RouteChip(
                    label = choice.label,
                    selected = state.exploitChoice == choice,
                    enabled = !state.busy && compatible,
                    incompatible = !compatible,
                    palette = palette,
                    modifier = Modifier.weight(1f)
                ) { actions.onSelectExploit(choice) }
            }
        }
        Text(
            text = routeSummary,
            color = palette.muted,
            fontSize = 11.5.sp,
            lineHeight = 17.sp,
            modifier = Modifier.padding(top = 8.dp)
        )

        // Collapsible supported kernels list
        Spacer(Modifier.height(12.dp))
        Box(
            Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(palette.innerBorder)
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
                .clickable(role = Role.Button) { kernelsExpanded = !kernelsExpanded }
                .padding(top = 11.dp, bottom = if (kernelsExpanded) 8.dp else 2.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Eyebrow(
                text = "已验证内核（${SupportedKernels.entries.size}）",
                color = palette.muted,
                modifier = Modifier.weight(1f)
            )
            Text(
                text = if (kernelsExpanded) "收起" else "展开查看",
                color = palette.foreground.copy(alpha = 0.78f),
                fontSize = 11.5.sp,
                fontWeight = FontWeight.SemiBold
            )
        }

        AnimatedVisibility(
            visible = kernelsExpanded,
            enter = fadeIn() + expandVertically(),
            exit = fadeOut() + shrinkVertically()
        ) {
            Column(
                Modifier.fillMaxWidth().padding(top = 4.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                SupportedKernels.entries.forEach { spec ->
                    KernelRow(
                        spec = spec,
                        isCurrentDevice = state.currentKernel == spec.version,
                        palette = palette
                    )
                }
            }
        }
    }
}

@Composable
private fun RouteChip(
    label: String,
    selected: Boolean,
    enabled: Boolean,
    incompatible: Boolean,
    palette: GlassPalette,
    modifier: Modifier,
    onClick: () -> Unit
) {
    val bg = when {
        selected -> palette.foreground.copy(alpha = 0.92f)
        incompatible -> palette.innerFill.copy(alpha = palette.innerFill.alpha * 0.55f)
        else -> palette.innerFill
    }
    val textColor = when {
        selected -> if (palette.dark) Color(0xFF060A09) else Color.White
        incompatible -> palette.subtle
        else -> palette.muted
    }

    Box(
        modifier
            .height(40.dp)
            .clip(CapsuleShape)
            .background(bg)
            .border(
                1.dp,
                if (selected) Color.Transparent else palette.innerBorder,
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
            text = if (incompatible) "$label · 不适用" else label,
            color = textColor,
            fontSize = if (incompatible) 11.sp else 12.5.sp,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(horizontal = 8.dp)
        )
    }
}

@Composable
private fun KernelRow(
    spec: SupportedKernelSpec,
    isCurrentDevice: Boolean,
    palette: GlassPalette
) {
    val borderColor = if (isCurrentDevice) {
        palette.foreground.copy(alpha = if (palette.dark) 0.24f else 0.18f)
    } else {
        palette.innerBorder
    }
    val fillColor = if (isCurrentDevice) {
        palette.foreground.copy(alpha = if (palette.dark) 0.075f else 0.055f)
    } else {
        palette.innerFill
    }

    Row(
        Modifier
            .fillMaxWidth()
            .clip(InnerShape)
            .background(fillColor)
            .border(1.dp, borderColor, InnerShape)
            .padding(horizontal = 11.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier
                .size(26.dp)
                .clip(CircleShape)
                .background(
                    if (isCurrentDevice) palette.positive.copy(alpha = 0.20f)
                    else palette.foreground.copy(alpha = if (palette.dark) 0.08f else 0.06f)
                ),
            contentAlignment = Alignment.Center
        ) {
            if (isCurrentDevice) {
                CheckIcon(color = palette.positive, modifier = Modifier.size(13.dp))
            } else {
                Text(
                    text = "${spec.index}",
                    color = palette.foreground,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace
                )
            }
        }
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(
                text = spec.version,
                color = palette.foreground,
                fontSize = 10.5.sp,
                lineHeight = 15.sp,
                fontFamily = FontFamily.Monospace
            )
            Row(
                Modifier.padding(top = 6.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (isCurrentDevice) {
                    KernelTag(
                        label = "当前设备",
                        highlighted = true,
                        accent = palette.positive,
                        palette = palette
                    )
                }
                spec.routes.forEach { route ->
                    KernelTag(
                        label = route.label,
                        highlighted = route == spec.preferredRoute,
                        accent = if (isCurrentDevice) palette.positive else palette.foreground,
                        palette = palette
                    )
                }
            }
        }
    }
}

@Composable
private fun KernelTag(
    label: String,
    highlighted: Boolean,
    accent: Color,
    palette: GlassPalette
) {
    val color = if (highlighted) accent else palette.muted
    Text(
        text = label,
        color = color,
        fontSize = 10.sp,
        fontWeight = FontWeight.Bold,
        letterSpacing = 0.2.sp,
        maxLines = 1,
        modifier = Modifier
            .clip(CapsuleShape)
            .background(
                color.copy(alpha = if (highlighted) (if (palette.dark) 0.14f else 0.10f) else 0.06f)
            )
            .border(
                1.dp,
                color.copy(alpha = if (highlighted) 0.30f else 0.12f),
                CapsuleShape
            )
            .padding(horizontal = 8.dp, vertical = 3.dp)
    )
}

@Composable
private fun LogPanel(
    state: UiState,
    actions: UiActions,
    backdrop: LayerBackdrop,
    palette: GlassPalette
) {
    val context = LocalContext.current
    var errorsOnly by remember { mutableStateOf(false) }
    var expanded by remember { mutableStateOf(false) }
    var copied by remember { mutableStateOf(false) }

    val displayed = remember(state.logEntries, errorsOnly) {
        if (errorsOnly) state.logEntries.filter { it.isError } else state.logEntries
    }
    val scroll = rememberScrollState()

    LaunchedEffect(displayed.size) {
        scroll.animateScrollTo(scroll.maxValue)
    }
    LaunchedEffect(copied) {
        if (copied) {
            delay(1800L)
            copied = false
        }
    }

    val logMaxHeight by animateDpAsState(
        targetValue = if (expanded) 300.dp else 152.dp,
        animationSpec = tween(durationMillis = 220, easing = FastOutSlowInEasing),
        label = "logHeight"
    )

    GlassCard(
        backdrop = backdrop,
        palette = palette
    ) {
        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Eyebrow("运行日志", palette.muted, Modifier.weight(1f))
            if (state.errorCount > 0) {
                ActionPill(
                    label = if (errorsOnly) "全部" else "错误 ${state.errorCount}",
                    color = if (errorsOnly) palette.foreground else palette.danger,
                    palette = palette
                ) { errorsOnly = !errorsOnly }
                Spacer(Modifier.width(6.dp))
            }
            if (displayed.isNotEmpty()) {
                ActionPill(
                    label = if (copied) "已复制" else "复制",
                    color = if (copied) palette.positive else palette.foreground,
                    palette = palette
                ) {
                    val plain = displayed.joinToString("\n") { "[${it.timestamp}] ${it.message}" }
                    copyToClipboard(context, "HOneClick Logs", plain)
                    copied = true
                }
                Spacer(Modifier.width(6.dp))
                ActionPill(
                    label = if (expanded) "收起" else "展开",
                    color = palette.muted,
                    palette = palette
                ) { expanded = !expanded }
                Spacer(Modifier.width(6.dp))
                ActionPill(
                    label = "清空",
                    color = palette.muted,
                    palette = palette,
                    onClick = actions::onClearLogs
                )
            }
        }

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 10.dp)
                .clip(InnerShape)
                .background(palette.innerFill)
                .border(1.dp, palette.innerBorder, InnerShape)
                .heightIn(
                    min = if (displayed.isEmpty()) 54.dp else 104.dp,
                    max = logMaxHeight
                )
                .verticalScroll(scroll)
                .padding(horizontal = 12.dp, vertical = 10.dp)
        ) {
            if (displayed.isEmpty()) {
                Text(
                    text = if (errorsOnly) "暂无错误日志" else "等待执行，运行记录与错误信息会实时显示在这里",
                    color = palette.muted,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.5.sp,
                    lineHeight = 18.sp
                )
            } else {
                SelectionContainer {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        displayed.forEach { entry ->
                            val lineColor = when {
                                entry.isError -> palette.danger
                                entry.isSuccess -> palette.positive
                                else -> palette.foreground.copy(alpha = 0.80f)
                            }
                            Text(
                                text = "${entry.timestamp}  ${entry.message}",
                                color = lineColor,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                lineHeight = 16.5.sp,
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ActionPill(
    label: String,
    color: Color,
    palette: GlassPalette,
    onClick: () -> Unit
) {
    Text(
        text = label,
        color = color,
        fontSize = 11.sp,
        fontWeight = FontWeight.SemiBold,
        maxLines = 1,
        modifier = Modifier
            .clip(CapsuleShape)
            .background(palette.innerFill)
            .border(1.dp, palette.innerBorder, CapsuleShape)
            .clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = 9.dp, vertical = 5.dp)
    )
}

@Composable
private fun Footer(palette: GlassPalette) {
    val uriHandler = LocalUriHandler.current
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 10.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "仅用于个人设备的安全研究，请勿用于非法用途",
            color = palette.muted,
            fontSize = 11.sp,
            lineHeight = 17.sp,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth()
        )
        Text(
            text = "使用本应用可能存在风险，请自行评估并承担相应风险",
            color = palette.muted,
            fontSize = 11.sp,
            lineHeight = 17.sp,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth()
        )
        Box(
            modifier = Modifier
                .padding(top = 6.dp)
                .clip(CapsuleShape)
                .clickable(role = Role.Button) {
                    uriHandler.openUri("https://github.com/superboyyy")
                }
                .padding(horizontal = 14.dp, vertical = 10.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = "github.com/superboyyy",
                color = palette.link,
                fontSize = 11.5.sp,
                fontWeight = FontWeight.SemiBold,
                fontFamily = FontFamily.Monospace
            )
        }
        Text(
            text = "HOneClick · $APP_VERSION_LABEL",
            color = palette.subtle,
            fontFamily = FontFamily.Monospace,
            fontSize = 10.5.sp,
            fontWeight = FontWeight.SemiBold,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth()
        )
    }
}

@Composable
private fun GlassCard(
    backdrop: LayerBackdrop,
    palette: GlassPalette,
    modifier: Modifier = Modifier,
    elevated: Boolean = false,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(
        modifier
            .fillMaxWidth()
            .liquidGlass(backdrop, palette, CardShape, elevated)
            .padding(17.dp),
        content = content
    )
}

@Composable
private fun LiquidProgress(
    progress: Float,
    accent: Color,
    busy: Boolean,
    palette: GlassPalette
) {
    val animatedProgress by animateFloatAsState(
        targetValue = (progress.coerceIn(0f, 100f) / 100f).coerceAtLeast(0.03f),
        animationSpec = tween(durationMillis = 480, easing = FastOutSlowInEasing),
        label = "progressFill"
    )
    val barColor by animateColorAsState(
        targetValue = accent,
        animationSpec = tween(durationMillis = 400),
        label = "progressColor"
    )
    val shimmerTransition = rememberInfiniteTransition(label = "progressShimmer")
    val shimmerOffset by shimmerTransition.animateFloat(
        initialValue = -0.35f,
        targetValue = 1.35f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1500, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "shimmerX"
    )

    Box(
        Modifier
            .fillMaxWidth()
            .height(8.dp)
            .clip(CapsuleShape)
            .background(palette.foreground.copy(alpha = if (palette.dark) 0.09f else 0.08f))
    ) {
        Canvas(
            Modifier
                .fillMaxWidth(animatedProgress)
                .height(8.dp)
                .clip(CapsuleShape)
        ) {
            drawRect(color = barColor.copy(alpha = 0.88f))
            if (busy && size.width > 0f) {
                val centerX = size.width * shimmerOffset
                val span = size.width * 0.45f
                drawRect(
                    brush = Brush.horizontalGradient(
                        colors = listOf(
                            Color.Transparent,
                            Color.White.copy(alpha = 0.42f),
                            Color.Transparent
                        ),
                        startX = centerX - span,
                        endX = centerX + span
                    )
                )
            }
        }
    }
}

@Composable
private fun CheckIcon(color: Color, modifier: Modifier = Modifier) {
    Canvas(modifier) {
        val path = Path().apply {
            moveTo(size.width * 0.18f, size.height * 0.52f)
            lineTo(size.width * 0.42f, size.height * 0.76f)
            lineTo(size.width * 0.84f, size.height * 0.26f)
        }
        drawPath(
            path = path,
            color = color,
            style = Stroke(
                width = (size.minDimension * 0.16f).coerceAtLeast(1.8.dp.toPx()),
                cap = StrokeCap.Round,
                join = StrokeJoin.Round
            )
        )
    }
}

@Composable
private fun CrossIcon(color: Color, modifier: Modifier = Modifier) {
    Canvas(modifier) {
        val stroke = Stroke(
            width = (size.minDimension * 0.18f).coerceAtLeast(1.8.dp.toPx()),
            cap = StrokeCap.Round
        )
        val inset = size.minDimension * 0.2f
        drawLine(
            color = color,
            start = Offset(inset, inset),
            end = Offset(size.width - inset, size.height - inset),
            strokeWidth = stroke.width,
            cap = StrokeCap.Round
        )
        drawLine(
            color = color,
            start = Offset(size.width - inset, inset),
            end = Offset(inset, size.height - inset),
            strokeWidth = stroke.width,
            cap = StrokeCap.Round
        )
    }
}

@Composable
private fun RunningSpinner(color: Color, modifier: Modifier = Modifier) {
    val transition = rememberInfiniteTransition(label = "spinner")
    val angle by transition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 950, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "spinAngle"
    )
    Canvas(modifier) {
        val stroke = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round)
        drawArc(
            color = color.copy(alpha = 0.22f),
            startAngle = 0f,
            sweepAngle = 360f,
            useCenter = false,
            style = stroke
        )
        drawArc(
            color = color,
            startAngle = angle,
            sweepAngle = 105f,
            useCenter = false,
            style = stroke
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
        text = text,
        color = color,
        fontSize = 10.5.sp,
        fontWeight = FontWeight.Bold,
        letterSpacing = 1.4.sp,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
        modifier = modifier
    )
}

@Composable
private fun Text(
    text: String,
    color: Color,
    modifier: Modifier = Modifier,
    fontSize: TextUnit = TextUnit.Unspecified,
    fontWeight: FontWeight? = null,
    fontFamily: FontFamily? = null,
    letterSpacing: TextUnit = TextUnit.Unspecified,
    lineHeight: TextUnit = TextUnit.Unspecified,
    textAlign: TextAlign? = null,
    maxLines: Int = Int.MAX_VALUE,
    overflow: TextOverflow = TextOverflow.Clip
) {
    BasicText(
        text = text,
        modifier = modifier,
        maxLines = maxLines,
        overflow = overflow,
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
    palette: GlassPalette,
    shape: RoundedCornerShape,
    elevated: Boolean = false
): Modifier =
    drawBackdrop(
        backdrop = backdrop,
        shape = { shape },
        effects = {
            vibrancy()
            blur((if (elevated) 18 else 14).dp.toPx())
            lens(
                refractionHeight = (if (elevated) 16 else 10).dp.toPx(),
                refractionAmount = (if (elevated) 30 else 20).dp.toPx(),
                chromaticAberration = false
            )
        },
        onDrawSurface = {
            drawRect(palette.cardFill)
        }
    )
        .border(
            width = 1.dp,
            brush = palette.borderBrush(elevated = elevated),
            shape = shape
        )
        .clip(shape)

private fun formatDuration(ms: Long): String {
    val tenths = ((ms.coerceAtLeast(0L) + 50L) / 100L)
    val seconds = tenths / 10L
    return if (seconds < 60L) {
        "$seconds.${tenths % 10L}s"
    } else {
        val mins = seconds / 60L
        val rem = seconds % 60L
        "${mins}m ${rem}s"
    }
}

private fun copyToClipboard(context: Context, label: String, text: String) {
    val clipboard = context.getSystemService(ClipboardManager::class.java) ?: return
    clipboard.setPrimaryClip(ClipData.newPlainText(label, text))
}

private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}
