package com.androidfprint.protocol

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Protocol error codes (`PROTOCOL.md` §9). Every code means deny. */
enum class ErrorCode(val code: Int) {
    BAD_REQUEST(1),
    UNSUPPORTED_VERSION(2),
    UNKNOWN_MESSAGE(3),
    NOT_PAIRED(4),
    REVOKED(5),
    USER_CANCELLED(6),
    BIOMETRIC_FAILED(7),
    RATE_LIMITED(8),
    EXPIRED(9),
    REPLAY(10),
    SIGNATURE_INVALID(11),
    CONTEXT_MISMATCH(12),
    INTERNAL(13);

    companion object {
        fun fromCode(code: Int): ErrorCode? = entries.firstOrNull { it.code == code }
    }
}

class ProtocolException(
    val errorCode: ErrorCode,
    message: String,
) : Exception(message)

typealias ProtocolResult<T> = Result<T>

/** Constants fixed by the specification. */
object Limits {
    const val PROTOCOL_VERSION = 1
    const val PROTOCOL_VERSION_LONG = 1L
    const val ID_LEN = 16
    const val CHALLENGE_LEN = 32
    const val PUBKEY_LEN = 65
    const val SIG_LEN = 64
    const val KEY_ID_LEN = 32
    const val ALGORITHM = "ES256"
    const val PAIRING_CODE_DIGITS = 6
    const val PAIRING_TTL = 120L
    const val AUTH_REQUEST_TTL_DEFAULT = 60L
    const val AUTH_REQUEST_TTL_MAX = 300L
    const val MAX_NAME_LEN = 64
    const val CLOCK_SKEW = 30L
    const val CLOCK_SKEW_STRICT = 10L

    const val SERVICE_TYPE = "_android-fprint._tcp.local."
}

/** Domain separators. Changing any of these requires a protocol version bump. */
object Domains {
    val SIGNING = "ANDROID_LINUX_AUTH_V1".toByteArray(Charsets.UTF_8)
    val PAIR = "ALP-PAIR-V1".toByteArray(Charsets.UTF_8)
    val SALT_PAIR = "ALP-PAIR-SALT-V1".toByteArray(Charsets.UTF_8)
    val DEVICE_CONFIRM = "ALP-DEVICE-CONFIRM-V1".toByteArray(Charsets.UTF_8)
    val HOST_CONFIRM = "ALP-HOST-CONFIRM-V1".toByteArray(Charsets.UTF_8)
    /** Expansion domain used only if rejection sampling exhausts the first block. */
    val PAIR_CODE = "ALP-PAIR-CODE-V1".toByteArray(Charsets.UTF_8)
}

/** Convenience for hex, which the CLI and the vector runner need. */
object Hex {
    fun encode(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    fun decode(s: String): ByteArray {
        require(s.length % 2 == 0) { "hex string must have an even length" }
        return ByteArray(s.length / 2) { i ->
            val hi = Character.digit(s[i * 2], 16)
            val lo = Character.digit(s[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "invalid hex digit at $i" }
            ((hi shl 4) or lo).toByte()
        }
    }
}

/**
 * A 16-byte opaque identifier: `host_id`, `device_id`, `request_id`, `session_id`.
 *
 * A plain class rather than a value class because Kotlin's generated value-class
 * equality would compare the underlying `ByteArray` by reference. Every identity
 * check in this project is a byte comparison, so that would make two equal ids
 * unequal and silently deny valid requests.
 */
class Id(val bytes: ByteArray) {
    init {
        require(bytes.size == Limits.ID_LEN) { "identifier must be ${Limits.ID_LEN} bytes" }
    }

    fun toHex(): String = Hex.encode(bytes)

    override fun equals(other: Any?): Boolean =
        this === other || (other is Id && bytes.contentEquals(other.bytes))

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun toString(): String = toHex()

    companion object {
        fun random(): Id {
            val b = ByteArray(Limits.ID_LEN)
            java.security.SecureRandom().nextBytes(b)
            return Id(b)
        }

        fun fromHex(s: String): Id = Id(Hex.decode(s))
    }
}

/** A 32-byte single-use authentication challenge. */
class Challenge(val bytes: ByteArray) {
    init {
        require(bytes.size == Limits.CHALLENGE_LEN) {
            "challenge must be ${Limits.CHALLENGE_LEN} bytes"
        }
    }

    fun toHex(): String = Hex.encode(bytes)

    override fun equals(other: Any?): Boolean =
        this === other || (other is Challenge && bytes.contentEquals(other.bytes))

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun toString(): String = toHex()

    companion object {
        fun random(): Challenge {
            val b = ByteArray(Limits.CHALLENGE_LEN)
            java.security.SecureRandom().nextBytes(b)
            return Challenge(b)
        }

        fun fromHex(s: String): Challenge = Challenge(Hex.decode(s))
    }
}

/**
 * What the phone is being asked to approve.
 *
 * The ten signed fields are the authorization scope. `displayHostName` and
 * `displayDetail` are deliberately **not** signed: they are operator-facing
 * prose, and signing attacker-supplied prose would give it authority it must not
 * have (`PROTOCOL.md` §8.1).
 */
data class AuthRequest(
    val requestId: Id,
    val hostId: Id,
    val deviceId: Id,
    val username: String,
    val purpose: String,
    val service: String,
    val operation: String,
    val challenge: Challenge,
    val issuedAt: Long,
    val expiresAt: Long,
    val sessionId: Id,
    val displayHostName: String? = null,
    val displayDetail: String? = null,
) {
    init {
        checkName("username", username)
        checkName("purpose", purpose)
        checkName("service", service)
        checkName("operation", operation)
        require(expiresAt >= issuedAt) { "expires_at precedes issued_at" }
        require(expiresAt - issuedAt <= Limits.AUTH_REQUEST_TTL_MAX) {
            "ttl exceeds ${Limits.AUTH_REQUEST_TTL_MAX}s"
        }
    }

    /** The canonical CBOR map of exactly the ten signed fields. */
    fun signedCore(): Cbor.Value.Map = Cbor.ofMap(
        "challenge" to Cbor.bytes(challenge.bytes),
        "device_id" to Cbor.bytes(deviceId.bytes),
        "expires_at" to Cbor.uint(expiresAt),
        "host_id" to Cbor.bytes(hostId.bytes),
        "issued_at" to Cbor.uint(issuedAt),
        "operation" to Cbor.text(operation),
        "purpose" to Cbor.text(purpose),
        "request_id" to Cbor.bytes(requestId.bytes),
        "service" to Cbor.text(service),
        "username" to Cbor.text(username),
    )

    /**
     * The exact bytes that get signed (`PROTOCOL.md` §8.2):
     * `"ANDROID_LINUX_AUTH_V1" || 0x00 || 0x01 || canonical_cbor(core)`.
     */
    fun signingInput(): ByteArray {
        val core = Cbor.encode(signedCore())
        val out = ByteArray(Domains.SIGNING.size + 2 + core.size)
        Domains.SIGNING.copyInto(out, 0)
        out[Domains.SIGNING.size] = 0x00
        out[Domains.SIGNING.size + 1] = Limits.PROTOCOL_VERSION.toByte()
        core.copyInto(out, Domains.SIGNING.size + 2)
        return out
    }

    fun signingInputDigest(): ByteArray = sha256(signingInput())

    fun toPayload(): ByteArray {
        val entries = mutableListOf(
            "challenge" to Cbor.bytes(challenge.bytes),
            "device_id" to Cbor.bytes(deviceId.bytes),
            "expires_at" to Cbor.uint(expiresAt),
            "host_id" to Cbor.bytes(hostId.bytes),
            "issued_at" to Cbor.uint(issuedAt),
            "operation" to Cbor.text(operation),
            "purpose" to Cbor.text(purpose),
            "request_id" to Cbor.bytes(requestId.bytes),
            "service" to Cbor.text(service),
            "session_id" to Cbor.bytes(sessionId.bytes),
            "username" to Cbor.text(username),
        )
        displayHostName?.let { entries += "display_host_name" to Cbor.text(it) }
        displayDetail?.let { entries += "display_detail" to Cbor.text(it) }
        return Cbor.encode(Cbor.ofMap(*entries.toTypedArray()))
    }

    companion object {
        val SIGNED_FIELDS = listOf(
            "challenge", "device_id", "expires_at", "host_id", "issued_at",
            "operation", "purpose", "request_id", "service", "username",
        )

        fun fromPayload(payload: ByteArray): AuthRequest {
            val v = Cbor.decode(payload) as? Cbor.Value.Map
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "auth_request is not a map")
            fun reqBytes(key: String): ByteArray =
                (v[key] as? Cbor.Value.Bytes)?.value
                    ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "missing or non-bytes field $key")
            fun reqText(key: String): String =
                (v[key] as? Cbor.Value.Text)?.value
                    ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "missing or non-text field $key")
            fun reqUint(key: String): Long =
                (v[key] as? Cbor.Value.Uint)?.value
                    ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "missing or non-uint field $key")

            val request = AuthRequest(
                requestId = Id(reqBytes("request_id")),
                hostId = Id(reqBytes("host_id")),
                deviceId = Id(reqBytes("device_id")),
                username = reqText("username"),
                purpose = reqText("purpose"),
                service = reqText("service"),
                operation = reqText("operation"),
                challenge = Challenge(reqBytes("challenge")),
                issuedAt = reqUint("issued_at"),
                expiresAt = reqUint("expires_at"),
                sessionId = Id(reqBytes("session_id")),
                displayHostName = (v["display_host_name"] as? Cbor.Value.Text)?.value,
                displayDetail = (v["display_detail"] as? Cbor.Value.Text)?.value,
            )
            // Every signed field must survive the round trip.
            val core = request.signedCore()
            for (f in SIGNED_FIELDS) {
                require(core[f] != null) { "signed field $f missing after decoding" }
            }
            return request
        }
    }
}

private fun checkName(field: String, value: String) {
    require(value.isNotEmpty()) { "$field must not be empty" }
    require(value.length <= Limits.MAX_NAME_LEN) { "$field exceeds ${Limits.MAX_NAME_LEN} characters" }
    require(!value.contains('\u0000')) { "$field contains NUL" }
}

data class SessionHello(
    val protocolVersion: Long = Limits.PROTOCOL_VERSION_LONG,
    val hostId: Id,
    val hostKeyId: String,
    val hostNonce: ByteArray,
    val sessionId: Id,
    val transports: List<String> = listOf("wifi", "ble"),
) {
    fun toPayload(): ByteArray = Cbor.encode(
        Cbor.ofMap(
            "host_id" to Cbor.bytes(hostId.bytes),
            "host_key_id" to Cbor.text(hostKeyId),
            "host_nonce" to Cbor.bytes(hostNonce),
            "protocol_version" to Cbor.uint(protocolVersion),
            "session_id" to Cbor.bytes(sessionId.bytes),
            "transports" to Cbor.array(transports.map { Cbor.text(it) }),
        )
    )

    companion object {
        fun fromPayload(payload: ByteArray): SessionHello {
            val v = Cbor.decode(payload) as? Cbor.Value.Map
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "session_hello is not a map")
            val nonce = (v["host_nonce"] as? Cbor.Value.Bytes)?.value
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "missing host_nonce")
            if (nonce.size != Limits.CHALLENGE_LEN) {
                throw ProtocolException(ErrorCode.BAD_REQUEST, "host_nonce must be 32 bytes")
            }
            val version = (v["protocol_version"] as? Cbor.Value.Uint)?.value
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "missing protocol_version")
            if (version != Limits.PROTOCOL_VERSION_LONG) {
                throw ProtocolException(ErrorCode.UNSUPPORTED_VERSION, "protocol_version $version")
            }
            val transports = ((v["transports"] as? Cbor.Value.Arr)?.items
                ?.map { (it as? Cbor.Value.Text)?.value ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "transports must be text") })
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "missing transports array")
            return SessionHello(
                protocolVersion = version,
                hostId = Id((v["host_id"] as Cbor.Value.Bytes).value),
                hostKeyId = (v["host_key_id"] as Cbor.Value.Text).value,
                hostNonce = nonce,
                sessionId = Id((v["session_id"] as Cbor.Value.Bytes).value),
                transports = transports,
            )
        }
    }
}

data class SessionHelloAck(
    val protocolVersion: Long = Limits.PROTOCOL_VERSION_LONG,
    val deviceId: Id,
    val deviceKeyId: String,
    val deviceNonce: ByteArray,
    val sessionId: Id,
) {
    fun toPayload(): ByteArray = Cbor.encode(
        Cbor.ofMap(
            "device_id" to Cbor.bytes(deviceId.bytes),
            "device_key_id" to Cbor.text(deviceKeyId),
            "device_nonce" to Cbor.bytes(deviceNonce),
            "protocol_version" to Cbor.uint(protocolVersion),
            "session_id" to Cbor.bytes(sessionId.bytes),
        )
    )

    companion object {
        fun fromPayload(payload: ByteArray): SessionHelloAck {
            val v = Cbor.decode(payload) as? Cbor.Value.Map
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "session_hello_ack is not a map")
            val nonce = (v["device_nonce"] as? Cbor.Value.Bytes)?.value
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "missing device_nonce")
            if (nonce.size != Limits.CHALLENGE_LEN) {
                throw ProtocolException(ErrorCode.BAD_REQUEST, "device_nonce must be 32 bytes")
            }
            return SessionHelloAck(
                protocolVersion = (v["protocol_version"] as Cbor.Value.Uint).value,
                deviceId = Id((v["device_id"] as Cbor.Value.Bytes).value),
                deviceKeyId = (v["device_key_id"] as Cbor.Value.Text).value,
                deviceNonce = nonce,
                sessionId = Id((v["session_id"] as Cbor.Value.Bytes).value),
            )
        }
    }
}

data class AuthResponse(
    val requestId: Id,
    val deviceId: Id,
    val sessionId: Id,
    val algorithm: String = Limits.ALGORITHM,
    val keyId: String,
    val signature: ByteArray,
) {
    init {
        require(signature.size == Limits.SIG_LEN) { "signature must be 64 bytes" }
        require(algorithm == Limits.ALGORITHM) { "unsupported algorithm $algorithm" }
    }

    fun toPayload(): ByteArray = Cbor.encode(
        Cbor.ofMap(
            "algorithm" to Cbor.text(algorithm),
            "device_id" to Cbor.bytes(deviceId.bytes),
            "key_id" to Cbor.text(keyId),
            "request_id" to Cbor.bytes(requestId.bytes),
            "session_id" to Cbor.bytes(sessionId.bytes),
            "signature" to Cbor.bytes(signature),
        )
    )

    companion object {
        fun fromPayload(payload: ByteArray): AuthResponse {
            val v = Cbor.decode(payload) as? Cbor.Value.Map
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "auth_response is not a map")
            val sig = (v["signature"] as? Cbor.Value.Bytes)?.value
                ?: throw ProtocolException(ErrorCode.SIGNATURE_INVALID, "missing signature")
            if (sig.size != Limits.SIG_LEN) {
                throw ProtocolException(ErrorCode.SIGNATURE_INVALID, "signature must be 64 bytes")
            }
            val algorithm = (v["algorithm"] as? Cbor.Value.Text)?.value
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "missing algorithm")
            if (algorithm != Limits.ALGORITHM) {
                throw ProtocolException(ErrorCode.BAD_REQUEST, "unsupported algorithm $algorithm")
            }
            return AuthResponse(
                requestId = Id((v["request_id"] as Cbor.Value.Bytes).value),
                deviceId = Id((v["device_id"] as Cbor.Value.Bytes).value),
                sessionId = Id((v["session_id"] as Cbor.Value.Bytes).value),
                algorithm = algorithm,
                keyId = (v["key_id"] as Cbor.Value.Text).value,
                signature = sig,
            )
        }
    }
}

data class AuthReject(val requestId: Id, val reason: Int) {
    fun toPayload(): ByteArray = Cbor.encode(
        Cbor.ofMap(
            "reason" to Cbor.uint(reason.toLong()),
            "request_id" to Cbor.bytes(requestId.bytes),
        )
    )

    companion object {
        fun fromPayload(payload: ByteArray): AuthReject {
            val v = Cbor.decode(payload) as? Cbor.Value.Map
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "auth_reject is not a map")
            return AuthReject(
                requestId = Id((v["request_id"] as Cbor.Value.Bytes).value),
                reason = ((v["reason"] as? Cbor.Value.Uint)?.value ?: 13L).toInt(),
            )
        }
    }
}

data class ErrorMessage(val code: Int, val message: String, val requestId: Id? = null) {
    fun toPayload(): ByteArray {
        val entries = mutableListOf(
            "code" to Cbor.uint(code.toLong()),
            "message" to Cbor.text(message),
        )
        requestId?.let { entries += "request_id" to Cbor.bytes(it.bytes) }
        return Cbor.encode(Cbor.ofMap(*entries.toTypedArray()))
    }

    companion object {
        fun fromPayload(payload: ByteArray): ErrorMessage {
            val v = Cbor.decode(payload) as? Cbor.Value.Map
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "error is not a map")
            return ErrorMessage(
                code = ((v["code"] as? Cbor.Value.Uint)?.value ?: 13L).toInt(),
                message = (v["message"] as? Cbor.Value.Text)?.value ?: "",
                requestId = (v["request_id"] as? Cbor.Value.Bytes)?.value?.let { Id(it) },
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

enum class CodeEntry(val wire: String) {
    /** The Linux host displays the code; the phone types it. */
    DEVICE("device"),

    /** The phone displays the code; the Linux host types it. */
    HOST("host"),
    ;

    companion object {
        fun fromWire(value: String): CodeEntry = when (value) {
            "device" -> DEVICE
            "host" -> HOST
            else -> throw ProtocolException(
                ErrorCode.BAD_REQUEST,
                "unknown code_entry \"$value\"; expected device or host",
            )
        }
    }
}

data class PairingStart(
    val sessionId: Id,
    val hostId: Id,
    val hostPublicKey: ByteArray,
    val hostKeyId: String,
    /** Operator-chosen code, or empty when the host chose none. */
    val code: String,
    /** Which endpoint must type the derived code. */
    val codeEntry: CodeEntry = CodeEntry.DEVICE,
    val expiresAt: Long,
    val hostNonce: ByteArray,
) {
    fun toPayload(): ByteArray = Cbor.encode(
        Cbor.ofMap(
            "code" to Cbor.text(code),
            "code_entry" to Cbor.text(codeEntry.wire),
            "expires_at" to Cbor.uint(expiresAt),
            "host_id" to Cbor.bytes(hostId.bytes),
            "host_key_id" to Cbor.text(hostKeyId),
            "host_nonce" to Cbor.bytes(hostNonce),
            "host_pubkey" to Cbor.bytes(hostPublicKey),
            "session_id" to Cbor.bytes(sessionId.bytes),
        )
    )

    companion object {
        fun fromPayload(payload: ByteArray): PairingStart {
            val v = Cbor.decode(payload) as? Cbor.Value.Map
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "pairing_start is not a map")
            val code = (v["code"] as? Cbor.Value.Text)?.value
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "missing code")
            if (code.isNotEmpty() &&
                (code.length != Limits.PAIRING_CODE_DIGITS || !code.all { it.isDigit() })
            ) {
                throw ProtocolException(ErrorCode.BAD_REQUEST, "code must be empty or six ASCII digits")
            }
            val codeEntry = when (val entry = v["code_entry"]) {
                null -> CodeEntry.DEVICE
                is Cbor.Value.Text -> CodeEntry.fromWire(entry.value)
                else -> throw ProtocolException(ErrorCode.BAD_REQUEST, "code_entry must be text")
            }
            val nonce = (v["host_nonce"] as? Cbor.Value.Bytes)?.value
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "missing host_nonce")
            if (nonce.size != Limits.CHALLENGE_LEN) {
                throw ProtocolException(ErrorCode.BAD_REQUEST, "host_nonce must be 32 bytes")
            }
            return PairingStart(
                sessionId = Id((v["session_id"] as Cbor.Value.Bytes).value),
                hostId = Id((v["host_id"] as Cbor.Value.Bytes).value),
                hostPublicKey = (v["host_pubkey"] as Cbor.Value.Bytes).value,
                hostKeyId = (v["host_key_id"] as Cbor.Value.Text).value,
                code = code,
                codeEntry = codeEntry,
                expiresAt = (v["expires_at"] as Cbor.Value.Uint).value,
                hostNonce = nonce,
            )
        }
    }
}

data class PairingSubmit(
    val sessionId: Id,
    val deviceId: Id,
    val deviceName: String,
    val devicePublicKey: ByteArray,
    val deviceKeyId: String,
    val deviceNonce: ByteArray,
    val mac: ByteArray,
    /** Revocation tokens for older pairings this phone asks the host to clean up. */
    val cleanupTokens: List<ByteArray> = emptyList(),
) {
    fun toPayload(): ByteArray {
        val entries = mutableListOf(
            "device_id" to Cbor.bytes(deviceId.bytes),
            "device_key_id" to Cbor.text(deviceKeyId),
            "device_name" to Cbor.text(deviceName),
            "device_nonce" to Cbor.bytes(deviceNonce),
            "device_pubkey" to Cbor.bytes(devicePublicKey),
            "mac" to Cbor.bytes(mac),
            "session_id" to Cbor.bytes(sessionId.bytes),
        )
        if (cleanupTokens.isNotEmpty()) {
            entries += "cleanup_tokens" to Cbor.array(cleanupTokens.map { Cbor.bytes(it) })
        }
        return Cbor.encode(Cbor.ofMap(*entries.toTypedArray()))
    }

    companion object {
        fun fromPayload(payload: ByteArray): PairingSubmit {
            val v = Cbor.decode(payload) as? Cbor.Value.Map
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "pairing_submit is not a map")
            val mac = (v["mac"] as? Cbor.Value.Bytes)?.value
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "missing mac")
            if (mac.size != 32) throw ProtocolException(ErrorCode.BAD_REQUEST, "mac must be 32 bytes")
            val nonce = (v["device_nonce"] as? Cbor.Value.Bytes)?.value
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "missing device_nonce")
            if (nonce.size != Limits.CHALLENGE_LEN) {
                throw ProtocolException(ErrorCode.BAD_REQUEST, "device_nonce must be 32 bytes")
            }
            val cleanupTokens = when (val raw = v["cleanup_tokens"]) {
                null -> emptyList()
                is Cbor.Value.Arr -> raw.items.map { entry ->
                    val bytes = (entry as? Cbor.Value.Bytes)?.value
                        ?: throw ProtocolException(
                            ErrorCode.BAD_REQUEST,
                            "cleanup_tokens entries must be byte strings",
                        )
                    if (bytes.size != 32) {
                        throw ProtocolException(
                            ErrorCode.BAD_REQUEST,
                            "cleanup_tokens entries must be 32 bytes",
                        )
                    }
                    bytes
                }
                else -> throw ProtocolException(
                    ErrorCode.BAD_REQUEST,
                    "cleanup_tokens must be an array",
                )
            }
            return PairingSubmit(
                sessionId = Id((v["session_id"] as Cbor.Value.Bytes).value),
                deviceId = Id((v["device_id"] as Cbor.Value.Bytes).value),
                deviceName = (v["device_name"] as Cbor.Value.Text).value,
                devicePublicKey = (v["device_pubkey"] as Cbor.Value.Bytes).value,
                deviceKeyId = (v["device_key_id"] as Cbor.Value.Text).value,
                deviceNonce = nonce,
                mac = mac,
                cleanupTokens = cleanupTokens,
            )
        }
    }
}

data class PairingResult(
    val sessionId: Id,
    val status: Long,
    val hostMac: ByteArray?,
    /** Bearer capability for revoking this pairing later. */
    val revocationToken: ByteArray? = null,
) {
    fun toPayload(): ByteArray {
        val entries = mutableListOf(
            "session_id" to Cbor.bytes(sessionId.bytes),
            "status" to Cbor.uint(status),
        )
        hostMac?.let { entries += "host_mac" to Cbor.bytes(it) }
        revocationToken?.let { entries += "revocation_token" to Cbor.bytes(it) }
        return Cbor.encode(Cbor.ofMap(*entries.toTypedArray()))
    }

    companion object {
        fun fromPayload(payload: ByteArray): PairingResult {
            val v = Cbor.decode(payload) as? Cbor.Value.Map
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "pairing_result is not a map")
            val status = (v["status"] as? Cbor.Value.Uint)?.value
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "missing status")
            if (status > 1L) throw ProtocolException(ErrorCode.BAD_REQUEST, "status must be 0 or 1")
            val hostMac = (v["host_mac"] as? Cbor.Value.Bytes)?.value
            if (status == 0L && hostMac == null) {
                throw ProtocolException(ErrorCode.BAD_REQUEST, "a success must carry host_mac")
            }
            val revocationToken = (v["revocation_token"] as? Cbor.Value.Bytes)?.value
            if (revocationToken != null && revocationToken.size != 32) {
                throw ProtocolException(
                    ErrorCode.BAD_REQUEST,
                    "revocation_token must be 32 bytes",
                )
            }
            return PairingResult(
                sessionId = Id((v["session_id"] as Cbor.Value.Bytes).value),
                status = status,
                hostMac = hostMac,
                revocationToken = revocationToken,
            )
        }
    }
}

/**
 * A device-initiated request to revoke its own pairing.
 *
 * The token is a bearer capability issued at pairing; it authorizes revocation
 * only. The host looks the token up by hash and marks the matching record revoked.
 */
data class Unpair(val token: ByteArray) {
    fun toPayload(): ByteArray = Cbor.encode(
        Cbor.ofMap("token" to Cbor.bytes(token)),
    )

    companion object {
        fun fromPayload(payload: ByteArray): Unpair {
            val v = Cbor.decode(payload) as? Cbor.Value.Map
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "unpair is not a map")
            val token = (v["token"] as? Cbor.Value.Bytes)?.value
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "missing token")
            if (token.size != 32) {
                throw ProtocolException(ErrorCode.BAD_REQUEST, "revocation token must be 32 bytes")
            }
            return Unpair(token)
        }
    }
}

/**
 * The device side of the pairing confirmation (`PROTOCOL.md` §6.4).
 *
 * The six-digit code is a function of *both* nonces, so neither side can know it
 * before the other has contributed one. This is why the exchange is two rounds.
 *
 * Limitations are documented in the specification: this is a keyed integrity
 * check over the transcript, not an information-theoretic SAS as in SPAKE2. It
 * does not provide forward secrecy.
 */
class PairingSession(val sessionId: Id, val hostNonce: ByteArray) {
    private var deviceNonce: ByteArray? = null
    private var secret: ByteArray? = null

    fun deriveWithDeviceNonce(nonce: ByteArray) {
        require(nonce.size == Limits.CHALLENGE_LEN) { "device nonce must be 32 bytes" }
        deviceNonce = nonce
        val ikm = hostNonce + nonce
        secret = hkdf(ikm = ikm, salt = Domains.SALT_PAIR, info = sessionId.bytes, length = 32)
        ikm.fill(0)
    }

    private fun confirmationKey(): ByteArray {
        val s = secret ?: throw IllegalStateException("deriveWithDeviceNonce must be called first")
        return hmac(s, Domains.PAIR + byteArrayOf(0x00) + sessionId.bytes)
    }

    /**
     * The six-digit code the operator types on the other endpoint.
     *
     * Rejection sampling, not a modulo reduction. `4_294_000_000` is the largest
     * multiple of `1_000_000` below `2^32`, so rejecting words at or above it
     * leaves every code 000000..999999 with exactly 4,294 chances. The expansion
     * is only reached with probability about 6e-30.
     */
    fun code(): String {
        val v = codeFromMaterial(confirmationKey())
        return v.toString().padStart(Limits.PAIRING_CODE_DIGITS, '0')
    }

    private fun codeFromMaterial(p: ByteArray): Long {
        val limit = 4_294_000_000L
        var block = p
        var counter = 0L
        while (true) {
            var i = 0
            while (i + 4 <= block.size) {
                val v = ((block[i].toLong() and 0xFF) shl 24) or
                    ((block[i + 1].toLong() and 0xFF) shl 16) or
                    ((block[i + 2].toLong() and 0xFF) shl 8) or
                    (block[i + 3].toLong() and 0xFF)
                if (v < limit) return v % 1_000_000L
                i += 4
            }
            counter += 1
            val msg = Domains.PAIR_CODE + byteArrayOf(0) + counter.toBigEndianBytes()
            block = hmac(p, msg)
        }
    }

    private fun Long.toBigEndianBytes(): ByteArray = ByteArray(8) { i ->
        (this ushr (56 - 8 * i)).toByte()
    }

    private fun transcript(hostId: Id, deviceId: Id, hostPub: ByteArray, devicePub: ByteArray): ByteArray =
        sessionId.bytes + hostId.bytes + deviceId.bytes + hostPub + devicePub + hostNonce +
            (deviceNonce ?: throw IllegalStateException("no device nonce"))

    fun deviceMac(hostId: Id, deviceId: Id, hostPub: ByteArray, devicePub: ByteArray): ByteArray =
        hmac(confirmationKey(), Domains.DEVICE_CONFIRM + byteArrayOf(0x00) +
            transcript(hostId, deviceId, hostPub, devicePub))

    fun hostMac(hostId: Id, deviceId: Id, hostPub: ByteArray, devicePub: ByteArray): ByteArray =
        hmac(confirmationKey(), Domains.HOST_CONFIRM + byteArrayOf(0x00) +
            transcript(hostId, deviceId, hostPub, devicePub))
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

object MessageType {
    const val PAIRING_START = 1
    const val PAIRING_SUBMIT = 2
    const val PAIRING_RESULT = 3
    const val SESSION_HELLO = 10
    const val SESSION_HELLO_ACK = 11
    const val AUTH_REQUEST = 12
    const val AUTH_RESPONSE = 13
    const val AUTH_REJECT = 14
    const val UNPAIR = 15
    const val ERROR = 20
}

/** The protocol message set (`PROTOCOL.md` §5). */
sealed class Message {
    abstract val type: Int
    abstract fun toPayload(): ByteArray

    data class PairingStartMessage(val v: PairingStart) : Message() {
        override val type = MessageType.PAIRING_START
        override fun toPayload() = v.toPayload()
    }

    data class PairingSubmitMessage(val v: PairingSubmit) : Message() {
        override val type = MessageType.PAIRING_SUBMIT
        override fun toPayload() = v.toPayload()
    }

    data class PairingResultMessage(val v: PairingResult) : Message() {
        override val type = MessageType.PAIRING_RESULT
        override fun toPayload() = v.toPayload()
    }

    data class SessionHelloMessage(val v: SessionHello) : Message() {
        override val type = MessageType.SESSION_HELLO
        override fun toPayload() = v.toPayload()
    }

    data class SessionHelloAckMessage(val v: SessionHelloAck) : Message() {
        override val type = MessageType.SESSION_HELLO_ACK
        override fun toPayload() = v.toPayload()
    }

    data class AuthRequestMessage(val v: AuthRequest) : Message() {
        override val type = MessageType.AUTH_REQUEST
        override fun toPayload() = v.toPayload()
    }

    data class AuthResponseMessage(val v: AuthResponse) : Message() {
        override val type = MessageType.AUTH_RESPONSE
        override fun toPayload() = v.toPayload()
    }

    data class AuthRejectMessage(val v: AuthReject) : Message() {
        override val type = MessageType.AUTH_REJECT
        override fun toPayload() = v.toPayload()
    }

    data class UnpairMessage(val v: Unpair) : Message() {
        override val type = MessageType.UNPAIR
        override fun toPayload() = v.toPayload()
    }

    data class ErrorMessageEnvelope(val v: ErrorMessage) : Message() {
        override val type = MessageType.ERROR
        override fun toPayload() = v.toPayload()
    }

    fun toFrame(): Frame = Frame(msgType = type, payload = toPayload())

    companion object {
        /** Parses a frame. An unassigned type is an error, never ignored. */
        fun fromFrame(frame: Frame): Message {
            if (frame.flags != 0) {
                throw ProtocolException(ErrorCode.UNSUPPORTED_VERSION, "nonzero frame flags")
            }
            return when (frame.msgType) {
                MessageType.PAIRING_START -> PairingStartMessage(PairingStart.fromPayload(frame.payload))
                MessageType.PAIRING_SUBMIT -> PairingSubmitMessage(PairingSubmit.fromPayload(frame.payload))
                MessageType.PAIRING_RESULT -> PairingResultMessage(PairingResult.fromPayload(frame.payload))
                MessageType.SESSION_HELLO -> SessionHelloMessage(SessionHello.fromPayload(frame.payload))
                MessageType.SESSION_HELLO_ACK -> SessionHelloAckMessage(SessionHelloAck.fromPayload(frame.payload))
                MessageType.AUTH_REQUEST -> AuthRequestMessage(AuthRequest.fromPayload(frame.payload))
                MessageType.AUTH_RESPONSE -> AuthResponseMessage(AuthResponse.fromPayload(frame.payload))
                MessageType.AUTH_REJECT -> AuthRejectMessage(AuthReject.fromPayload(frame.payload))
                MessageType.UNPAIR -> UnpairMessage(Unpair.fromPayload(frame.payload))
                MessageType.ERROR -> ErrorMessageEnvelope(ErrorMessage.fromPayload(frame.payload))
                else -> throw ProtocolException(ErrorCode.UNKNOWN_MESSAGE, "unknown message type ${frame.msgType}")
            }
        }

        fun fromBytes(bytes: ByteArray): Message {
            val (frame, _) = Frame.decode(bytes)
                ?: throw ProtocolException(ErrorCode.BAD_REQUEST, "incomplete frame")
            return fromFrame(frame)
        }
    }
}

// ---------------------------------------------------------------------------
// Cryptographic helpers
// ---------------------------------------------------------------------------

fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

fun hmac(key: ByteArray, data: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(data)
}

/**
 * HKDF-SHA-256 (extract-then-expand), matching the specification.
 *
 * Per RFC 5869 the salt is used exactly as supplied; an absent salt is treated as
 * `HashLen` zero bytes. There is no special case for a salt that happens to be
 * hash-length: such a salt is still an HMAC key, not a pre-computed PRK.
 */
fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    val extractKey = if (salt.isEmpty()) ByteArray(32) else salt
    mac.init(SecretKeySpec(extractKey, "HmacSHA256"))
    val prk = mac.doFinal(ikm)

    val out = ByteArray(length)
    var previous = ByteArray(0)
    var offset = 0
    var counter = 1
    val expander = Mac.getInstance("HmacSHA256")
    expander.init(SecretKeySpec(prk, "HmacSHA256"))
    while (offset < length) {
        expander.reset()
        expander.update(previous)
        expander.update(info)
        expander.update(counter.toByte())
        previous = expander.doFinal()
        val take = minOf(previous.size, length - offset)
        previous.copyInto(out, offset, 0, take)
        offset += take
        counter++
    }
    prk.fill(0)
    return out
}

/** Constant-time comparison, so MAC verification cannot be timed. */
fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
    if (a.size != b.size) return false
    var diff = 0
    for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
    return diff == 0
}