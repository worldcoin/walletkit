package org.world.walletkit

import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import org.junit.Test
import uniffi.walletkit_core.FlamingoException
import uniffi.walletkit_core.FlamingoLiveCapture
import uniffi.walletkit_core.FlamingoMatchRequest
import uniffi.walletkit_core.FlamingoMatcher
import uniffi.walletkit_core.RequestDigestSigner
import uniffi.walletkit_core.RequestIntegrityException
import uniffi.walletkit_core.RequestIntegrityPlatform
import uniffi.walletkit_core.RequestIntegrityProvider
import uniffi.walletkit_core.RequestIntegritySession
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.fail

private class IntegrityTestSigner(private val fails: Boolean = false) : RequestDigestSigner {
    val calls = AtomicInteger()

    override fun signDigest(clientDataHash: ByteArray): ByteArray {
        assertContentEquals(ByteArray(32) { 0xA5.toByte() }, clientDataHash)
        calls.incrementAndGet()
        if (fails) throw RequestIntegrityException.SigningFailed()
        return byteArrayOf(1, 2, 3)
    }
}

private class IntegrityTestProvider(
    val signer: IntegrityTestSigner,
    private val fails: Boolean = false,
) : RequestIntegrityProvider {
    val calls = AtomicInteger()

    override suspend fun prepare(): RequestIntegritySession {
        yield()
        calls.incrementAndGet()
        if (fails) throw RequestIntegrityException.Unavailable()
        return RequestIntegritySession("test-key-token", RequestIntegrityPlatform.ANDROID, signer)
    }
}

class RequestIntegrityTest {
    private fun request() = FlamingoMatchRequest.GrayBadge(
        FlamingoLiveCapture.Vanilla(byteArrayOf(1)),
        byteArrayOf(2),
        0.5,
    )

    private fun matcher(provider: IntegrityTestProvider) = FlamingoMatcher(
        "https://verifier.invalid", provider,
    ).dangerouslySkipMeasurements()

    @Test
    fun preparesEachAttemptAndSignsMockDigestBeforeFailingClosed() = runTest {
        val signer = IntegrityTestSigner()
        val provider = IntegrityTestProvider(signer)

        matcher(provider).use { configured ->
            repeat(2) {
                try {
                    configured.performMatch(request())
                    fail("mock signing must stop before transport")
                } catch (_: FlamingoException.CanonicalSigningUnavailable) {}
            }
        }

        assertEquals(2, provider.calls.get())
        assertEquals(2, signer.calls.get())
    }

    @Test
    fun preservesTypedProviderFailureWithoutSigning() = runTest {
        val signer = IntegrityTestSigner()
        val provider = IntegrityTestProvider(signer, fails = true)

        matcher(provider).use { configured ->
            try {
                configured.performMatch(request())
                fail("provider failure must propagate")
            } catch (failure: FlamingoException.RequestIntegrity) {
                assertIs<RequestIntegrityException.Unavailable>(failure.v1)
            }
        }

        assertEquals(0, signer.calls.get())
    }

    @Test
    fun preservesTypedSignerFailure() = runTest {
        val provider = IntegrityTestProvider(IntegrityTestSigner(fails = true))

        matcher(provider).use { configured ->
            try {
                configured.performMatch(request())
                fail("signer failure must propagate")
            } catch (failure: FlamingoException.RequestIntegrity) {
                assertIs<RequestIntegrityException.SigningFailed>(failure.v1)
            }
        }

        assertEquals(1, provider.signer.calls.get())
    }
}
