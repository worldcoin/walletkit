package org.world.walletkit

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class AtomicBlobStoreTests {
    @Test
    fun writeReadDelete() {
        val root = tempDirectory()
        val store = FileBlobStore(root)
        val path = "account_keys.bin"
        val payload = byteArrayOf(1, 2, 3, 4)

        store.writeAtomic(path, payload)
        val readBack = store.read(path)
        assertEquals(payload.toList(), readBack?.toList())

        store.delete(path)
        assertNull(store.read(path))

        root.deleteRecursively()
    }
}
