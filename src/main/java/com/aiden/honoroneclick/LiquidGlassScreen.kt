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
                DevicePanel(state, backdrop, foreground, muted, dark)
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
            "仅用于个人设备的安全研究。",
            color = muted,
            fontSize = 11.sp,
            lineHeight = 18.sp,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth()
        )
        Text(
            "使用本应用可能存在风险，请自行评估并承担相应风险。",
            color = muted,
            fontSize = 11.sp,
            lineHeight = 18.sp,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth()
        )
        Text(
            "请勿用于非法用途。",
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
            text = "WKL",
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
        Modifier.fillMaxWidth().padding(vertical = 8.dp),
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
        Column(Modifier.padding(start = 15.dp)) {
            Text(
                "HONOR / PRIVILEGE LAB",
                color = muted,
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.8.sp
            )
            Text(
                "OneClick",
                color = foreground,
                fontSize = 34.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = (-1.2).sp
            )
        }
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
        Eyebrow("SYSTEM STATE", muted)
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
    backdrop: LayerBackdrop,
    foreground: Color,
    muted: Color,
    dark: Boolean
) {
    GlassCard(backdrop, foreground, dark) {
        Eyebrow("DEVICE PROFILE", muted)
        Text(
            "Magic9 Pro Max",
            color = foreground,
            fontSize = 26.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(top = 7.dp)
        )
        Text(
            "${state.model}  ·  ${state.device}",
            color = muted,
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
            letterSpacing = 0.8.sp,
            modifier = Modifier.padding(top = 3.dp)
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
            Eyebrow("LIVE LOG", muted, Modifier.weight(1f))
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
                text = state.logs,
                color = foreground.copy(alpha = 0.78f),
                fontFamily = FontFamily.Monospace,
                fontSize = 11.5.sp,
                lineHeight = 18.sp,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(210.dp)
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
