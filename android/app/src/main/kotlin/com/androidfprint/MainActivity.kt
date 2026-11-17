package com.androidfprint

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.lifecycle.lifecycleScope
import androidx.fragment.app.FragmentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androidfprint.biometric.rememberBiometricGatekeeper
import com.androidfprint.keystore.DeviceAuthKey
import com.androidfprint.protocol.Id
import com.androidfprint.session.AuthenticatorSession
import com.androidfprint.session.HostStore
import com.androidfprint.ui.AuthenticatorScreen

/**
 * The single activity.
 *
 * It owns the session and renders whatever the session last decided. All protocol
 * and cryptographic decisions live in [AuthenticatorSession] and
 * [DeviceAuthKey]; this class exists only to bridge Android's activity model to
 * Compose.
 */
class MainActivity : FragmentActivity() {

    private var deviceKey: DeviceAuthKey? = null
    private var session: AuthenticatorSession? = null
    private var deviceId: Id? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        DeviceAuthKey.initialize(applicationContext)
        val key = DeviceAuthKey()
        deviceKey = key

        // The device identifier is random and stored alongside the app's own data.
        // It is not derived from the device name, the MAC address or the Android ID.
        val id = DeviceIdentity.load(this)
        val activeSession = AuthenticatorSession(
            context = applicationContext,
            key = key,
            deviceId = id,
            deviceName = DeviceIdentity.name(this),
            // Paired hosts outlive the process, so they are reloaded here rather than
            // held by the session.
            hosts = HostStore(applicationContext),
            scope = lifecycleScope,
        )
        deviceId = id
        session = activeSession

        setContent {
            MaterialTheme {
                val state by activeSession.state.collectAsStateWithLifecycle()
                val gatekeeper = rememberBiometricGatekeeper()

                LaunchedEffect(Unit) {
                    activeSession.setAvailability(key.capabilities()?.strongBiometricEnrolled == true)
                    activeSession.connect()
                }

                Surface {
                    AuthenticatorScreen(
                        state = state,
                        deviceId = id.toHex(),
                        deviceName = DeviceIdentity.name(this@MainActivity),
                        capabilities = key.capabilities(),
                        hosts = activeSession.knownHosts(),
                        // The session validates a request before it ever reaches the
                        // screen; tapping Authenticate starts the biometric check.
                        onAuthenticate = {
                            activeSession.beginBiometricCheck(
                                activity = this@MainActivity,
                                executor = androidx.core.content.ContextCompat.getMainExecutor(
                                    this@MainActivity,
                                ),
                                availability = gatekeeper.availability(),
                            )
                        },
                        onDecline = { activeSession.declinePending() },
                    )
                }
            }
        }
    }
}

/**
 * The app's stable identity.
 *
 * A random 128-bit identifier generated once and kept in private storage. It is
 * deliberately *not* derived from anything the platform exposes about the device:
 * identity must come from the key, and the identifier only names the key in logs
 * and on the Linux side.
 */
object DeviceIdentity {
    private const val PREFS = "phone-auth-identity"
    private const val KEY_ID = "device_id"
    private const val KEY_NAME = "device_name"

    fun load(context: android.content.Context): Id {
        val prefs = context.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)
        prefs.getString(KEY_ID, null)?.let { existing ->
            return runCatching { Id.fromHex(existing) }.getOrElse { generate(prefs) }
        }
        return generate(prefs)
    }

    private fun generate(prefs: android.content.SharedPreferences): Id {
        val id = Id.random()
        prefs.edit().putString(KEY_ID, id.toHex()).apply()
        return id
    }

    fun name(context: android.content.Context): String =
        context.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)
            .getString(KEY_NAME, null)
            ?: run {
                val model = android.os.Build.MODEL ?: "Android"
                val label = "$model".replace(Regex("[^A-Za-z0-9 _-]"), "").trim().take(32)
                    .ifEmpty { "Android device" }
                context.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)
                    .edit().putString(KEY_NAME, label).apply()
                label
            }
}
