import Foundation

public final class IOSStorageProvider: StorageProvider {
    private let keystoreImpl: IOSDeviceKeystore
    private let blobStoreImpl: IOSAtomicBlobStore
    private let pathsImpl: StoragePaths

    public init(
        rootDirectory: URL,
        keystoreService: String = "walletkit.devicekeystore",
        keystoreAccount: String = "default"
    ) throws {
        let worldidDir = rootDirectory.appendingPathComponent("worldid", isDirectory: true)
        do {
            try FileManager.default.createDirectory(
                at: worldidDir,
                withIntermediateDirectories: true
            )
        } catch {
            throw StorageError.BlobStore("failed to create storage directory: \(error)")
        }

        self.pathsImpl = StoragePaths.fromRoot(root: rootDirectory.path)
        self.keystoreImpl = IOSDeviceKeystore(
            service: keystoreService,
            account: keystoreAccount
        )
        self.blobStoreImpl = IOSAtomicBlobStore(baseURL: worldidDir)
    }

    public func keystore() -> DeviceKeystore {
        keystoreImpl
    }

    public func blobStore() -> AtomicBlobStore {
        blobStoreImpl
    }

    public func paths() -> StoragePaths {
        pathsImpl
    }
}

public enum WalletKitStorage {
    public static func makeDefaultProvider(
        bundleIdentifier: String? = Bundle.main.bundleIdentifier
    ) throws -> IOSStorageProvider {
        let fileManager = FileManager.default
        guard let appSupport = fileManager.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            throw StorageError.BlobStore("missing application support directory")
        }
        let bundleId = bundleIdentifier ?? "walletkit"
        let root = appSupport.appendingPathComponent(bundleId, isDirectory: true)
        return try IOSStorageProvider(rootDirectory: root)
    }
}
