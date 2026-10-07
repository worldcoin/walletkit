import Foundation
internal import walletkit_coreFFI

/// Implementations must support calls from background threads. Do not re-enter the calling store.
/// Use authenticated encryption under a device-bound key; reject mismatched associated data.
public protocol DeviceKeystore: Sendable {
  func seal(associatedData: Data, plaintext: Data) throws -> Data
  func openSealed(associatedData: Data, ciphertext: Data) throws -> Data
}
/// Thread-safe blob I/O. Writes must atomically replace the complete blob; failures must throw.
public protocol AtomicBlobStore: Sendable {
  func read(path: String) throws -> Data?
  func writeAtomic(path: String, bytes: Data) throws
  func delete(path: String) throws
}
public protocol Logger: Sendable {
  func log(level: LogLevel, message: String)
}
public protocol VaultChangedListener: Sendable { func onVaultChanged() }
public protocol ActivityChangedListener: Sendable { func onActivityChanged() }

/// Supplies authentication material before each attested Flamingo connection or reassignment.
/// The host owns token acquisition, refresh, audience policy, and hardware-key lifecycle.
/// Throw ``RequestIntegrityError`` to report a typed failure; other errors become
/// ``RequestIntegrityError/callbackFailed``.
public protocol RequestIntegrityProvider: Sendable {
  func prepare() async throws -> RequestIntegritySession
}

/// Signs a 32-byte SHA-256 client-data digest with the key certified by the session token,
/// returning the platform's native signature encoding. Called on a background thread.
public protocol RequestDigestSigner: Sendable {
  func signDigest(clientDataHash: Data) throws -> Data
}

// Callback tables pass one retain of a `Callback` box to Rust, which releases it exactly once.
private final class Callback: Sendable {
  let target: any Sendable
  init(_ target: any Sendable) { self.target = target }
}

private func retain(_ target: any Sendable) -> UnsafeMutableRawPointer {
  Unmanaged.passRetained(Callback(target)).toOpaque()
}

private func target<T>(_ context: UnsafeMutableRawPointer?, as _: T.Type) throws -> T {
  guard let context,
    let target = Unmanaged<Callback>.fromOpaque(context).takeUnretainedValue().target as? T
  else { throw WalletKitBridgeError(code: "InvalidCallback") }
  return target
}

private let releaseContext: @convention(c) (UnsafeMutableRawPointer?) -> Void = { context in
  guard let context else { return }
  Unmanaged<Callback>.fromOpaque(context).release()
}

private func data(_ slice: WalletKitByteSlice) -> Data {
  guard let pointer = slice.data, slice.len > 0 else { return Data() }
  return Data(bytes: pointer, count: slice.len)
}

private func string(_ slice: WalletKitByteSlice) -> String {
  String(decoding: data(slice), as: UTF8.self)
}

private func copy(_ data: Data) -> WalletKitBuffer {
  data.withUnsafeBytes {
    walletkit_buffer_copy($0.bindMemory(to: UInt8.self).baseAddress, $0.count)
  }
}

/// Runs a storage callback. `StorageError`s cross with their variant; anything else is
/// reported as `HostFailure` without the host's message, which may contain secrets.
private func storage(
  _ outError: UnsafeMutablePointer<WalletKitBuffer>?, _ body: () throws -> Void
) -> Bool {
  do {
    try body()
    return true
  } catch let error as StorageError {
    outError?.pointee = copy(ByteWriter.encode { error.write(&$0) })
    return false
  } catch {
    return false
  }
}

func keystoreCallbacks(_ keystore: any DeviceKeystore) -> WalletKitDeviceKeystoreCallbacks {
  WalletKitDeviceKeystoreCallbacks(
    context: retain(keystore),
    seal: { context, associatedData, plaintext, out, outError in
      storage(outError) {
        let sealed = try target(context, as: (any DeviceKeystore).self)
          .seal(associatedData: data(associatedData), plaintext: data(plaintext))
        out?.pointee = copy(sealed)
      }
    },
    open_sealed: { context, associatedData, ciphertext, out, outError in
      storage(outError) {
        let opened = try target(context, as: (any DeviceKeystore).self)
          .openSealed(associatedData: data(associatedData), ciphertext: data(ciphertext))
        out?.pointee = copy(opened)
      }
    },
    release: releaseContext)
}

func blobStoreCallbacks(_ blobStore: any AtomicBlobStore) -> WalletKitAtomicBlobStoreCallbacks {
  WalletKitAtomicBlobStoreCallbacks(
    context: retain(blobStore),
    read: { context, path, out, outError in
      storage(outError) {
        if let blob = try target(context, as: (any AtomicBlobStore).self).read(path: string(path)) {
          out?.pointee = copy(blob)
        }
      }
    },
    write_atomic: { context, path, bytes, outError in
      storage(outError) {
        try target(context, as: (any AtomicBlobStore).self)
          .writeAtomic(path: string(path), bytes: data(bytes))
      }
    },
    delete_blob: { context, path, outError in
      storage(outError) {
        try target(context, as: (any AtomicBlobStore).self).delete(path: string(path))
      }
    },
    release: releaseContext)
}

func loggerCallbacks(_ logger: any Logger) -> WalletKitLoggerCallbacks {
  WalletKitLoggerCallbacks(
    context: retain(logger),
    log: { context, level, message in
      guard let logger = try? target(context, as: (any Logger).self),
        let level = try? element(level, of: LogLevel.ordinals)
      else { return }
      logger.log(level: level, message: string(message))
    },
    release: releaseContext)
}

func vaultListenerCallbacks(
  _ listener: any VaultChangedListener
) -> WalletKitVaultChangedListenerCallbacks {
  WalletKitVaultChangedListenerCallbacks(
    context: retain(listener),
    on_vault_changed: { context in
      try? target(context, as: (any VaultChangedListener).self).onVaultChanged()
    },
    release: releaseContext)
}

func activityListenerCallbacks(
  _ listener: any ActivityChangedListener
) -> WalletKitActivityChangedListenerCallbacks {
  WalletKitActivityChangedListenerCallbacks(
    context: retain(listener),
    on_activity_changed: { context in
      try? target(context, as: (any ActivityChangedListener).self).onActivityChanged()
    },
    release: releaseContext)
}

func integrityProviderCallbacks(
  _ provider: any RequestIntegrityProvider
) -> WalletKitRequestIntegrityProviderCallbacks {
  WalletKitRequestIntegrityProviderCallbacks(
    context: retain(provider),
    prepare: { context, completion in
      guard let provider = try? target(context, as: (any RequestIntegrityProvider).self) else {
        return walletkit_request_integrity_failed(
          completion, ordinal(.callbackFailed, in: RequestIntegrityError.ordinals))
      }
      Task {
        do {
          let session = try await provider.prepare()
          withByteSlice(session.token) { token in
            walletkit_request_integrity_prepared(
              completion, token, ordinal(session.platform, in: RequestIntegrityPlatform.ordinals),
              signerCallbacks(session.signer))
          }
        } catch let error as RequestIntegrityError {
          walletkit_request_integrity_failed(
            completion, ordinal(error, in: RequestIntegrityError.ordinals))
        } catch {
          // Host messages may contain secrets; only the failure class crosses.
          walletkit_request_integrity_failed(
            completion, ordinal(.callbackFailed, in: RequestIntegrityError.ordinals))
        }
      }
    },
    release: releaseContext)
}

private func signerCallbacks(
  _ signer: any RequestDigestSigner
) -> WalletKitRequestDigestSignerCallbacks {
  WalletKitRequestDigestSignerCallbacks(
    context: retain(signer),
    sign_digest: { context, digest, out in
      guard let signer = try? target(context, as: (any RequestDigestSigner).self),
        let signature = try? signer.signDigest(clientDataHash: data(digest))
      else { return false }
      out?.pointee = copy(signature)
      return true
    },
    release: releaseContext)
}
