package com.androidfprint.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.androidfprint.keystore.DeviceAuthKey
import com.androidfprint.session.KnownHost
import com.androidfprint.session.SessionState

/**
 * The whole user interface.
 *
 * It is intentionally small, because its job is not to be pleasant but to be
 * *informative*: the operator must always be able to see which host, which user and
 * which action they are approving. Anything that would hide that context is a
 * security bug, not a design shortcut.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuthenticatorScreen(
    state: SessionState,
    deviceId: String,
    deviceName: String,
    capabilities: DeviceAuthKey.Capabilities?,
    hosts: List<KnownHost>,
    /** Called when the operator taps Authenticate. */
    onAuthenticate: () -> Unit,
    onDecline: () -> Unit,
    modifier: Modifier = Modifier,
) {
    // The screen is purely presentational: the session decides whether a request may
    // be shown at all, and this composable only renders the resulting state.

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text("Linux authenticator") },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            DeviceHeader(deviceId, deviceName, capabilities)

            when (state) {
                is SessionState.Idle -> IdlePanel(hosts, onAuthenticate)
                is SessionState.AwaitingApproval -> ApprovalPanel(
                    state = state,
                    onApprove = onAuthenticate,
                    onDecline = onDecline,
                )
                is SessionState.PairingAwaitingCode -> PairingCodePanel(state)
                is SessionState.AwaitingBiometric -> BusyPanel("Waiting for biometric confirmation…")
                is SessionState.Approved -> ApprovedPanel(state)
                is SessionState.Denied -> DeniedPanel(state)
                is SessionState.PairingConfirmed -> InfoPanel("Pairing complete", "This host can now request authentication.")
                is SessionState.Failed -> FailurePanel(state)
            }
        }
    }
}

@Composable
private fun DeviceHeader(
    deviceId: String,
    deviceName: String,
    capabilities: DeviceAuthKey.Capabilities?,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(deviceName, style = MaterialTheme.typography.titleMedium)
            Text(
                "device ${deviceId.take(16)}…",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
            )
            capabilities?.let { caps ->
                Text(
                    buildString {
                        append(
                            when (caps.location) {
                                DeviceAuthKey.KeyLocation.STRONGBOX -> "StrongBox"
                                DeviceAuthKey.KeyLocation.HARDWARE -> "hardware-backed keystore"
                                DeviceAuthKey.KeyLocation.SOFTWARE -> "software keystore"
                            },
                        )
                        append(" · ")
                        append(
                            if (caps.strongBiometricEnrolled) {
                                "strong biometric enrolled"
                            } else {
                                "no strong biometric enrolled"
                            },
                        )
                    },
                    style = MaterialTheme.typography.bodySmall,
                )
                if (!caps.strongBiometricEnrolled) {
                    // Never silently downgrade: say so explicitly.
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Filled.Warning,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.height(18.dp),
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "This device cannot perform the cryptographic authentication this app requires.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun IdlePanel(hosts: List<KnownHost>, onAuthenticate: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            "Waiting for a Linux host to request authentication.",
            style = MaterialTheme.typography.bodyLarge,
        )
        if (hosts.isEmpty()) {
            Text(
                "No hosts are paired yet. Start pairing from the Linux machine with " +
                    "`phone-authctl pair`, then compare the code on both screens.",
                style = MaterialTheme.typography.bodyMedium,
            )
        } else {
            Text("Paired hosts:", style = MaterialTheme.typography.titleSmall)
            hosts.forEach { host ->
                Text(
                    "• ${host.hostName} (${host.hostId.toHex().take(16)}…)",
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
    }
}

/**
 * The approval screen.
 *
 * Everything the host asked for is on display, and the operator has both an
 * approve and a decline action. The detail text, when present, is visibly marked
 * as unverified because it is not covered by the signature.
 */
@Composable
private fun ApprovalPanel(
    state: SessionState.AwaitingApproval,
    onApprove: () -> Unit,
    onDecline: () -> Unit,
) {
    val request = state.request
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text("Authorize", style = MaterialTheme.typography.headlineSmall)

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Field("Host", request.displayHostName ?: request.hostId.toHex())
                Field("User", request.username)
                Field("Action", request.purpose)
                if (request.service != request.purpose) Field("Service", request.service)
                Field("Operation", request.operation)
            }
        }

        request.displayDetail?.let { detail ->
            Card(
                Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant,
                ),
            ) {
                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.Top) {
                    Icon(
                        Icons.Filled.Info,
                        contentDescription = "Unverified detail",
                        modifier = Modifier.height(20.dp),
                    )
                    Spacer(Modifier.height(8.dp))
                    Column {
                        Text(
                            "Unverified detail from Linux (not covered by the signature)",
                            style = MaterialTheme.typography.labelMedium,
                        )
                        Text(detail, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = onApprove, modifier = Modifier.weight(1f)) {
                Icon(Icons.Filled.Fingerprint, contentDescription = null)
                Spacer(Modifier.height(8.dp))
                Text("Authenticate")
            }
            OutlinedButton(onClick = onDecline, modifier = Modifier.weight(1f)) {
                Text("Decline")
            }
        }
    }
}

@Composable
private fun Field(label: String, value: String) {
    Row {
        Text(
            "$label:",
            style = MaterialTheme.typography.labelLarge,
            modifier = Modifier.padding(end = 8.dp),
        )
        Text(value, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun PairingCodePanel(state: SessionState.PairingAwaitingCode) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Pairing request", style = MaterialTheme.typography.titleMedium)
        Text(
            "Compare this code with the one shown on the Linux machine. " +
                "Only continue if they match exactly.",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
        )
        Box(
            modifier = Modifier
                .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(12.dp))
                .padding(horizontal = 32.dp, vertical = 20.dp),
        ) {
            Text(
                state.code.chunked(3).joinToString(" "),
                fontSize = 34.sp,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
            )
        }
        Text(
            "Host: ${state.hostName}",
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

@Composable
private fun ApprovedPanel(state: SessionState.Approved) {
    InfoPanel(
        "Authenticated",
        "Signed for ${state.request.username} on ${state.request.displayHostName ?: "this host"}.",
    )
}

@Composable
private fun DeniedPanel(state: SessionState.Denied) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("Not authorised", style = MaterialTheme.typography.titleMedium)
            Text(state.reason, style = MaterialTheme.typography.bodyMedium)
            Text(
                "request ${state.requestId.take(16)}…",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
            )
        }
    }
}

@Composable
private fun BusyPanel(message: String) {
    Text(message, style = MaterialTheme.typography.bodyLarge)
}

@Composable
private fun InfoPanel(title: String, body: String) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(title, style = MaterialTheme.typography.titleMedium)
        Text(body, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun FailurePanel(state: SessionState.Failed) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("Error", style = MaterialTheme.typography.titleMedium)
            Text(state.message, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

private val UnusedColorGuard: Color = Color.Unspecified