package org.world.walletkit

import java.util.concurrent.CancellationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull

/** Frozen encodings shared with `crates/walletkit/src/native/values.rs`. */
class CodecTest {
    private fun bytes(hex: String) = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private val entries =
        listOf(
            ActivityEntry(
                1u,
                ULong.MAX_VALUE,
                "app",
                "zażółć",
                ProtocolVersion.V4,
                100u,
                ActivityOutcome.FAILED,
                listOf(7uL, ULong.MAX_VALUE),
                ActivityFailureReason.RELYING_PARTY_REJECTED,
            ),
            ActivityEntry(null, 2u, "", "c", ProtocolVersion.V3, null, ActivityOutcome.COMPLETED, emptyList(), null),
        )

    @Test fun recordsAndListsDecode() {
        assertEquals(
            entries,
            NativeReader.decode(
                bytes(
                    "02000000010100000000000000ffffffffffffffff030000006170700a0000007a61c5bcc3b3c582c4870101640000000000000003020000000700000000000000ffffffffffffffff01040002000000000000000000000001000000630000000000000000",
                ),
            ) {
                list { readActivityEntry() }
            },
        )
        assertEquals(
            listOf(
                CredentialRecord(1u, ULong.MAX_VALUE, 3u, 4u, true),
            ),
            NativeReader.decode(bytes("010000000100000000000000ffffffffffffffff0300000000000000040000000000000001")) {
                list { readCredentialRecord() }
            },
        )
        assertEquals(
            CredentialConstraintsCheckResult(
                false,
                listOf(CredentialConstraintsCheckItem("orb", 9u, true)),
            ),
            NativeReader.decode(bytes("0001000000030000006f7262090000000000000001")) {
                readCredentialConstraintsCheckResult()
            },
        )
        assertEquals(
            RecoveryData("0xa", "pk", "c"),
            NativeReader.decode(bytes("0300000030786102000000706b0100000063")) { readRecoveryData() },
        )
        val signature =
            NativeReader.decode(bytes("03000000010203000000000000000000000000000000000000000000000000000000000000002a")) {
                readRecoveryUpdateSignature()
            }
        assertContentEquals(byteArrayOf(1, 2, 3), signature.signature)
        assertEquals(Uint256.fromHex("2a"), signature.nonce)
        assertEquals(RecoveryBinding("a", null, "t"), NativeReader.decode(bytes("01010000006100010100000074")) { readRecoveryBinding() })
        assertEquals(listOf("a", null), NativeReader.decode(bytes("0200000001010000006100")) { list { optional { string() } } })
        assertEquals(listOf("0x01"), NativeReader.decode(bytes("010000000400000030783031")) { list { string() } })
    }

    @Test fun statusesAndOutcomesDecode() {
        assertEquals(GatewayRequestStatus.Submitted("0x1"), NativeReader.decode(bytes("0203000000307831")) { readGatewayRequestStatus() })
        assertEquals(
            GatewayRequestStatus.Failed("e", "c"),
            NativeReader.decode(bytes("040100000065010100000063")) { readGatewayRequestStatus() },
        )
        assertEquals(RegistrationStatus.Finalized, NativeReader.decode(bytes("03")) { readRegistrationStatus() })
        assertEquals(RegistrationStatus.Failed("e", null), NativeReader.decode(bytes("04010000006500")) { readRegistrationStatus() })
        assertEquals(
            FlamingoMatchOutcome.Rejected(
                FlamingoMatchRejection.ImageRejected(
                    FlamingoImageRole.LIVE_SELFIE,
                    FlamingoImageFailureReason.NOISY_THERMAL_IMAGE,
                    FlamingoValidationTarget.LIGHT_GUARD_PAIR,
                ),
                FlamingoDebugReport.OmittedTooLarge(5u),
            ),
            NativeReader.decode(bytes("0106012a0103020500000000000000")) { readFlamingoMatchOutcome() },
        )
        assertEquals(
            FlamingoMatchOutcome.Rejected(
                FlamingoMatchRejection.InputRejected(FlamingoInputFailureReason.TOTAL_IMAGES_TOO_LARGE, null, 10u),
                FlamingoDebugReport.Available("{}"),
            ),
            NativeReader.decode(bytes("01040500010a0000000000000000020000007b7d")) { readFlamingoMatchOutcome() },
        )
    }

    @Test fun errorsDecodeIntoTypedExceptions() {
        assertIs<CancellationException>(decodeNativeError(bytes("000900000043616e63656c6c6564")))
        val network = assertIs<WalletKitException.NetworkError>(decodeNativeError(bytes("01040100000075010000006501f701")))
        assertEquals(Triple("u", "e", 503.toUShort()), Triple(network.url, network.error, network.status))
        val storage = assertIs<WalletKitException.Storage>(decodeNativeError(bytes("01000b01000000000000000200000000000000")))
        val leaf = assertIs<StorageException.InvalidLeafIndex>(storage.value0)
        assertEquals(1uL to 2uL, leaf.expected to leaf.provided)
        assertEquals("denied", assertIs<StorageException.Keystore>(decodeNativeError(bytes("02000600000064656e696564"))).value0)
        val input = assertIs<FlamingoException.InvalidInput>(decodeNativeError(bytes("03000100000061010000007201010900000000000000")))
        assertEquals(FlamingoInputFailureKind.TOO_LARGE, input.kind)
        assertEquals(9uL, input.limitBytes)
        assertIs<RequestIntegrityException.TimedOut>(
            assertIs<FlamingoException.RequestIntegrity>(decodeNativeError(bytes("030204"))).value0,
        )
        assertIs<CredentialConstraintsCheckException.ConstraintTooDeep>(decodeNativeError(bytes("0401")))
    }

    @Test fun inputsEncodeToFrozenBytes() {
        assertEquals(
            "010100000000000000ffffffffffffffff030000006170700a0000007a61c5bcc3b3c582c4870101640000000000000003020000000700000000000000ffffffffffffffff0104",
            hex(NativeWriter.encode { writeActivityEntry(entries[0]) }),
        )
        assertEquals("01000000010000006b0100000076", hex(NativeWriter.encode { writeStringMap(mapOf("k" to "v")) }))
        assertEquals("010000000200000001000000ab", hex(NativeWriter.encode { writeMeasurements(mapOf(2u to byteArrayOf(0xab.toByte()))) }))
        val deepFace =
            FlamingoMatchRequest.DeepFace(
                byteArrayOf(1),
                FlamingoLiveCapture.LightGuard(byteArrayOf(2), byteArrayOf(3), FlamingoMatchingFrame.UNILLUMINATED),
                byteArrayOf(4),
                "{}".encodeToByteArray(),
                0.5,
            )
        assertEquals(
            "0001000000010101000000020100000003010100000004020000007b7d000000000000e03f",
            hex(
                NativeWriter.encode {
                    writeFlamingoMatchRequest(deepFace)
                },
            ),
        )
        val grayBadge = FlamingoMatchRequest.GrayBadge(FlamingoLiveCapture.Vanilla(byteArrayOf(5)), byteArrayOf(), 1.0)
        assertEquals("0100010000000500000000000000000000f03f", hex(NativeWriter.encode { writeFlamingoMatchRequest(grayBadge) }))
        assertEquals("000600000064656e696564", hex(NativeBridge.callbackError(StorageException.Keystore("denied"))!!))
        assertNull(NativeBridge.callbackError(IllegalStateException("private")))
    }

    @Test fun malformedResultsAreRejected() {
        for (bad in listOf("", "0300000030786102000000706b010000006300", "02ffffff", "0400000000")) {
            assertFailsWith<WalletKitBridgeException> { NativeReader.decode(bytes(bad)) { readRecoveryData() } }
        }
        assertFailsWith<WalletKitBridgeException> { NativeReader.decode(bytes("05")) { readGatewayRequestStatus() } }
        assertFailsWith<WalletKitBridgeException> { NativeReader.decode(bytes("02")) { bool() } }
    }

    @Test fun handlesFromAFailedDecodeAreReleased() {
        val field = FieldElement.fromU64(5u)
        val id = field.handle.id
        val truncated =
            NativeWriter.encode {
                u32(1u)
                u64(id.toULong())
            }
        assertFailsWith<WalletKitBridgeException> {
            NativeReader.decode(truncated) { list { FieldElement(handle()) }.also { u8() } }
        }
        assertFailsWith<WalletKitBridgeException> { field.toHexString() }
    }
}
