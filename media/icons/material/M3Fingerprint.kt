package com.example.fprint

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp

/* ---------- 1. Theme: wallpaper colors on Android 12+, static fallback below ---------- */
@Composable
fun AppTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit,
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (darkTheme) dynamicDarkColorScheme(LocalContext.current)
            else dynamicLightColorScheme(LocalContext.current)
        darkTheme -> darkColorScheme()
        else -> lightColorScheme()
    }
    // For the Expressive motion/shape layer, swap MaterialTheme for
    // MaterialExpressiveTheme(colorScheme = ..., motionScheme = MotionScheme.expressive())
    // (experimental API, needs a recent androidx.compose.material3).
    MaterialTheme(colorScheme = colorScheme, content = content)
}

/* ---------- 2. Which roles paint the icon ---------- */
enum class FingerprintStyle { Tonal, Bold, Accent, Neutral }

private fun ColorScheme.fingerprintColors(style: FingerprintStyle): Pair<Color, Color> = when (style) {
    FingerprintStyle.Tonal   -> primaryContainer to onPrimaryContainer          // recommended default
    FingerprintStyle.Bold    -> primary to onPrimary                            // loud, expressive
    FingerprintStyle.Accent  -> tertiaryContainer to onTertiaryContainer        // contrasting accent
    FingerprintStyle.Neutral -> surfaceContainerHighest to onSurfaceVariant     // matches the plain light/dark versions
}

/* ---------- 3. The icon ---------- */
@Composable
fun FingerprintBadge(
    modifier: Modifier = Modifier,
    style: FingerprintStyle = FingerprintStyle.Tonal,
) {
    val (container, content) = MaterialTheme.colorScheme.fingerprintColors(style)

    Surface(
        modifier = modifier.size(96.dp),
        shape = CircleShape,
        color = container,
        shadowElevation = 6.dp,            // real elevation shadow under the disc
    ) {
        Box(Modifier.padding(18.dp)) {
            // ridge shadow: same glyph, black, offset down, low alpha
            Icon(
                painter = painterResource(R.drawable.ic_fprint),
                contentDescription = null,
                tint = Color.Black.copy(alpha = 0.28f),
                modifier = Modifier.offset(y = 1.5.dp),
            )
            Icon(
                painter = painterResource(R.drawable.ic_fprint),
                contentDescription = "Fingerprint",
                tint = content,
            )
        }
    }
}
