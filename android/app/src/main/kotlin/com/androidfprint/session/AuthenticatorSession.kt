package com.androidfprint.session

import android.content.Context
import com.androidfprint.biometric.BiometricAvailability
import com.androidfprint.biometric.BiometricOutcome
import com.androidfprint.biometric.authenticateStrong
import com.androidfprint.keystore.DeviceAuthKey
import com.androidfprint.protocol.AuthRequest
import com.androidfprint.protocol.AuthResponse
import com.androidfprint.protocol.Challenge
import com.androidfprint.protocol.ErrorCode
import com.androidfprint.protocol.Frame
import com.androidfprint.protocol.Hex
import com.androidfprint.protocol.Id
import com.androidfprint.protocol.Limits
import com.androidfprint.protocol.Message
import com.androidfprint.protocol.PairingResult
import com.androidfprint.protocol.PairingSession
import com.androidfprint.protocol.PairingStart
import com.androidfprint.protocol.PairingSubmit
import com.androidfprint.protocol.ProtocolException
import com.androidfprint.protocol.SessionHello
import com.androidfprint.protocol.SessionHelloAck
import com.androidfprint.protocol.sha256
import com.androidfprint.transport.BleTransport
import com.androidfprint.transport.WifiTransport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException
import java.security.cert.X509Certificate
import java.util.concurrent.Executor

/**
 * One place where a request can be shown, decided and answered.
 *
 * The ordering here is the security property, and it is not negotiable:
 *
 * 1. The request is parsed and validated.
 * 2. Its **signed** context is displayed to the operator.
 * 3. The operator is asked.
 * 4. A strong biometric check runs.
 * 5. Only then is the Keystore key asked to sign.
 *
 * Nothing is signed before the operator has seen the context, and nothing is sent
 * unless the signature succeeded.
 */
sealed interface SessionState {
    data object Idle : SessionState

    data class PairingAwaitingCode(val code: String, val hostName: String) : SessionState

    data class PairingConfirmed(val code: String) : SessionState

    /** A request is on screen, waiting for the operator. */
    data class AwaitingApproval(val request: AuthRequest) : SessionState

    /** A biometric prompt is in front of the operator. */
    data class AwaitingBiometric(val request: AuthRequest) : SessionState

    /** Signed and sent. */
    data class Approved(val request: AuthRequest) : SessionState

    /** Denied, with the reason shown to the operator. */
    data class Denied(val requestId: String, val reason: String) : SessionState

    data class Failed(val message: String) : SessionState
}

/**
 * Drives one connection to a Linux host.
 *
 * Transport-independent by construction: it works over [`WifiTransport`] or
 * [`BleTransport`], and which one is in use cannot change whether a request is
 * approved.
 */
class AuthenticatorSession(
    private val context: Context,
    private val key: DeviceAuthKey,
    private val deviceId: Id,
    private val deviceName: String,
    /** Paired hosts, persisted. A phone pairs with more than one PC. */
    private val hosts: HostStore,
    /** Scope for background work; supplied by the activity's lifecycle. */
    @Suppress("unused") private val scope: CoroutineScope,
) {

    private val _state = MutableStateFlow<SessionState>(SessionState.Idle)
    val state: StateFlow<SessionState> = _state

    /**
     * Hosts this device has paired with, read through to [HostStore].
     *
     * Not a local list: the user pairs a second PC, the app is restarted by the system
     * at some point, and an in-memory list would silently forget the first one. The
     * forgotten host is indistinguishable from a revoked one, which is the kind of
     * problem that arrives as "the app sometimes stops working".
     */

    /**
     * The request the operator is currently deciding, if any.
     *
     * Held explicitly rather than inferred from the UI so the session owns the
     * decision, not the composable.
     */
    private var pendingRequest: AuthRequest? = null

    /**
     * A request may never be signed on the back of a biometric success that
     * belonged to a different request.
     *
     * This is bound when the operator approves, and cleared as soon as a signature
     * is produced or the request is abandoned. It is the session-level guard
     * against a stale biometric result authorising a later request.
     */
    private var approvedRequestId: String? = null

    /** Whether this device can satisfy the strong-biometric policy at all. */
    @Volatile
    private var strongBiometricAvailable: Boolean = false

    init {
        key.ensureKey()
    }

    /**
     * Records a completed pairing, replacing any earlier record for the same host.
     *
     * Only ever called once the transcript has completed and the reciprocal MAC has
     * verified, so a failed pairing cannot leave a usable record behind.
     */
    fun addKnownHost(host: KnownHost) {
        hosts.put(host)
    }

    fun knownHosts(): List<KnownHost> = hosts.all()

    /** Forgets one host. Returns whether it was actually paired. */
    fun forgetHost(hostId: com.androidfprint.protocol.Id): Boolean = hosts.remove(hostId)

    /** Records whether a strong biometric is enrolled, for policy decisions. */
    fun setAvailability(available: Boolean) {
        strongBiometricAvailable = available
    }

    /** The request awaiting the operator's decision, if any. */
    fun pendingRequest(): AuthRequest? = pendingRequest

    /**
     * Called when the operator declines. No prompt is shown and nothing is signed.
     */
    fun declinePending() {
        pendingRequest?.let { reject(it) }
        pendingRequest = null
        approvedRequestId = null
    }

    /**
     * Entry point for the transport layer: a request arrived.
     *
     * The session validates it and, only if it may be shown, moves to
     * [SessionState.AwaitingApproval]. Everything else is refused without
     * troubling the operator.
     */
    fun offerRequest(request: AuthRequest) {
        if (!strongBiometricAvailable) {
            // Refuse up front: a prompt that cannot succeed is just a way to train
            // the operator to tap through dialogs.
            send(
                Message.AuthRejectMessage(
                    com.androidfprint.protocol.AuthReject(
                        request.requestId,
                        ErrorCode.BIOMETRIC_FAILED.code,
                    ),
                ).toFrame(),
            )
            _state.value = SessionState.Denied(
                request.requestId.toHex(),
                "this device has no strong biometric enrolled",
            )
            return
        }
        requestApproval(request)
    }

    /** Prepares the session to receive messages over whichever transport connects. */
    fun connect() {
        sender = { frame -> transportSink?.invoke(frame) }
    }

    /** Installed by the active transport adapter. */
    var transportSink: ((Frame) -> Unit)? = null

    // -----------------------------------------------------------------------
    // Pairing
    // -----------------------------------------------------------------------

    /**
     * Completes the device half of pairing.
     *
     * The code is derived from both nonces, so it can only be computed here, after
     * the host's nonce has arrived. The operator compares the two screens; nothing
     * is persisted until the reciprocal MAC verifies.
     */
    fun handlePairingStart(start: PairingStart): SessionState {
        return try {
            if (start.hostPublicKey.size != Limits.PUBKEY_LEN) {
                return fail("host public key is malformed")
            }
            val deviceNonce = ByteArray(Limits.CHALLENGE_LEN).also {
                java.security.SecureRandom().nextBytes(it)
            }
            val session = PairingSession(start.sessionId, start.hostNonce)
            session.deriveWithDeviceNonce(deviceNonce)

            val code = session.code()
            // When the operator pre-selected a code, both sides must derive the same
            // value; a mismatch means the comparison they intended cannot succeed.
            if (start.code.isNotEmpty() && start.code != code) {
                return fail("the code shown on the phone does not match the chosen code")
            }

            _state.value = SessionState.PairingAwaitingCode(code, deviceName)

            val publicKeyBytes = key.publicKeyBytes()
                ?: return fail("the device key is unavailable; re-enrolment may have invalidated it")
            val devicePublicKeyId = Hex.encode(sha256(publicKeyBytes))

            val mac = session.deviceMac(
                start.hostId, deviceId, start.hostPublicKey, publicKeyBytes,
            )
            val submit = PairingSubmit(
                sessionId = start.sessionId,
                deviceId = deviceId,
                deviceName = deviceName,
                devicePublicKey = publicKeyBytes,
                deviceKeyId = devicePublicKeyId,
                deviceNonce = deviceNonce,
                mac = mac,
            )
            send(Message.PairingSubmitMessage(submit).toFrame())
            SessionState.PairingAwaitingCode(code, deviceName)
        } catch (e: Exception) {
            fail(e.message ?: "pairing failed")
        }
    }

    /** Verifies the host's reciprocal MAC, which completes pairing. */
    fun handlePairingResult(
        result: PairingResult,
        session: PairingSession,
        hostPublicKey: ByteArray,
        hostId: Id,
        pinnedCertificate: X509Certificate?,
    ): SessionState {
        return try {
            if (result.status != 0L) return fail("the host rejected the pairing")
            val hostMac = result.hostMac ?: return fail("the host did not confirm pairing")
            val devicePublicKey = key.publicKeyBytes() ?: return fail("device key unavailable")
            val expected = session.hostMac(hostId, deviceId, hostPublicKey, devicePublicKey)
            if (!com.androidfprint.protocol.constantTimeEquals(hostMac, expected)) {
                // The host did not prove it derived the same secret, so the code the
                // operator compared did not authenticate this exchange.
                return fail("pairing confirmation failed")
            }
            addKnownHost(
                KnownHost(
                    hostId = hostId,
                    keyId = Hex.encode(sha256(hostPublicKey)),
                    publicKeyBytes = hostPublicKey,
                    pinnedCertificate = pinnedCertificate,
                    hostName = deviceName,
                ),
            )
            _state.value = SessionState.PairingConfirmed("")
            SessionState.PairingConfirmed("")
        } catch (e: Exception) {
            fail(e.message ?: "pairing verification failed")
        }
    }

    // -----------------------------------------------------------------------
    // Authentication
    // -----------------------------------------------------------------------

    /**
     * Presents a request to the operator and signs it if they approve.
     *
     */
    fun requestApproval(request: AuthRequest) {
        // Refuse anything we cannot attribute to a paired host before showing
        // the operator anything at all.
        if (hosts.all().none { it.hostId == request.hostId }) {
            _state.value = SessionState.Denied(
                request.requestId.toHex(),
                "this Linux host is not paired with this phone",
            )
            send(
                Message.AuthRejectMessage(
                    com.androidfprint.protocol.AuthReject(
                        request.requestId,
                        ErrorCode.NOT_PAIRED.code,
                    ),
                ).toFrame(),
            )
            return
        }
        if (request.deviceId != deviceId) {
            _state.value = SessionState.Denied(
                request.requestId.toHex(),
                "this request is addressed to a different device",
            )
            return
        }

        // Rate limiting on the device side, so a malicious host cannot spam the
        // operator with prompts.
        if (requestPromptCount >= MAX_PROMPTS_PER_WINDOW) {
            _state.value = SessionState.Denied(
                request.requestId.toHex(),
                "too many requests; try again later",
            )
            send(
                Message.AuthRejectMessage(
                    com.androidfprint.protocol.AuthReject(
                        request.requestId,
                        ErrorCode.RATE_LIMITED.code,
                    ),
                ).toFrame(),
            )
            return
        }
        requestPromptCount++

        pendingRequest = request
        _state.value = SessionState.AwaitingApproval(request)
    }

    /**
     * Runs the biometric check for the request the operator has just approved.
     *
     * Kept separate from [requestApproval] so the ordering is explicit at the call
     * site: show the context, then approve, then authenticate, then sign.
     *
     * @param activity a `FragmentActivity`, which `BiometricPrompt` requires.
     * @param executor the executor for the prompt callbacks.
     * @param availability what this device can actually offer.
     */
    fun beginBiometricCheck(
        activity: androidx.fragment.app.FragmentActivity,
        executor: Executor,
        availability: BiometricAvailability,
    ) {
        val request = pendingRequest ?: return
        // The operator's approval is bound to this exact request id.
        approvedRequestId = request.requestId.toHex()
        _state.value = SessionState.AwaitingBiometric(request)

        authenticateStrong(
            activity = activity,
            executor = executor,
            availability = availability,
            title = "Linux authentication",
            subtitle = request.username,
            description = describe(request),
            onResult = { outcome -> onBiometricResult(request, outcome) },
        )
    }

    /**
     * Operator declined. No prompt is shown and nothing is signed.
     */
    fun reject(request: AuthRequest, reason: ErrorCode = ErrorCode.USER_CANCELLED) {
        approvedRequestId = null
        _state.value = SessionState.Denied(request.requestId.toHex(), "declined")
        send(
            Message.AuthRejectMessage(
                com.androidfprint.protocol.AuthReject(request.requestId, reason.code),
            ).toFrame(),
        )
    }

    private fun onBiometricResult(request: AuthRequest, outcome: BiometricOutcome) {
        when (outcome) {
            is BiometricOutcome.Succeeded -> signAndSend(request)
            is BiometricOutcome.NotRecognised -> Unit // the prompt is still up
            is BiometricOutcome.Failed -> {
                val reason = when (outcome.code) {
                    androidx.biometric.BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                    androidx.biometric.BiometricPrompt.ERROR_USER_CANCELED,
                    -> "declined"
                    else -> outcome.message
                }
                reject(request, ErrorCode.USER_CANCELLED)
                _state.value = SessionState.Denied(request.requestId.toHex(), reason)
            }
            is BiometricOutcome.Unavailable -> {
                // A device that cannot satisfy the strong-biometric policy must say
                // so plainly rather than quietly proceed.
                reject(request, ErrorCode.BIOMETRIC_FAILED)
                _state.value = SessionState.Denied(
                    request.requestId.toHex(),
                    unavailableMessage(outcome.reason),
                )
            }
        }
    }

    private fun unavailableMessage(reason: BiometricAvailability): String = when (reason) {
        is BiometricAvailability.NotEnrolled ->
            "no strong biometric is enrolled; add a fingerprint or a strong face model"
        is BiometricAvailability.NoHardware ->
            "this device has no biometric sensor that can be used for authentication"
        is BiometricAvailability.TemporarilyUnavailable -> "biometrics unavailable: ${reason.reason}"
        is BiometricAvailability.InsufficientStrength ->
            "this device does not provide a strong biometric that can be used for " +
                "cryptographic authentication (available: ${reason.available.joinToString()})"
        BiometricAvailability.Available -> "biometrics unavailable"
    }

    /**
     * Signs the request and sends the response.
     *
     * The signature covers [AuthRequest.signingInput], which binds the domain
     * separator, the protocol version and exactly the ten signed fields. Nothing
     * else is signed, so no unsigned display text can gain authority.
     */
    private fun signAndSend(request: AuthRequest) {
        // The biometric that just succeeded must belong to *this* request.
        if (approvedRequestId != request.requestId.toHex()) {
            reject(request, ErrorCode.INTERNAL)
            _state.value = SessionState.Denied(
                request.requestId.toHex(),
                "the confirmation did not match this request",
            )
            return
        }
        val signature = key.sign(request.signingInput())
        if (signature == null) {
            // Keystore refused: no recent strong authentication, or the key was
            // invalidated by a re-enrollment. Either way this is a denial.
            reject(request, ErrorCode.BIOMETRIC_FAILED)
            _state.value = SessionState.Denied(
                request.requestId.toHex(),
                "the device key could not sign; re-pairing may be required",
            )
            return
        }
        val publicKeyBytes = key.publicKeyBytes() ?: return
        val response = AuthResponse(
            requestId = request.requestId,
            deviceId = deviceId,
            sessionId = request.sessionId,
            keyId = Hex.encode(sha256(publicKeyBytes)),
            signature = signature,
        )
        send(Message.AuthResponseMessage(response).toFrame())
        approvedRequestId = null
        pendingRequest = null
        _state.value = SessionState.Approved(request)
    }

    /** Human-readable summary of exactly what is being authorised. */
    private fun describe(request: AuthRequest): String = buildString {
        append("Host: ${request.displayHostName ?: request.hostId.toHex()}\n")
        append("User: ${request.username}\n")
        append("Action: ${request.purpose}")
        if (request.service != request.purpose) append(" (${request.service})")
    }

    private fun fail(message: String): SessionState {
        _state.value = SessionState.Failed(message)
        return _state.value
    }

    // -----------------------------------------------------------------------
    // Transport plumbing
    // -----------------------------------------------------------------------

    /** Set by the transport layer; kept abstract so both transports work. */
    var sender: ((Frame) -> Unit)? = null

    private fun send(frame: Frame) {
        sender?.invoke(frame)
    }

    private var requestPromptCount = 0

    private companion object {
        const val MAX_PROMPTS_PER_WINDOW = 5
    }
}