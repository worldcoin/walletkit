import Foundation

public final class IOSAtomicBlobStore: AtomicBlobStore {
    private let baseURL: URL
    private let fileManager = FileManager.default

    public init(baseURL: URL) {
        self.baseURL = baseURL
    }

    public func read(path: String) throws -> Data? {
        let url = baseURL.appendingPathComponent(path)
        guard fileManager.fileExists(atPath: url.path) else {
            return nil
        }
        do {
            return try Data(contentsOf: url)
        } catch {
            throw StorageError.BlobStore("read failed: \(error)")
        }
    }

    public func writeAtomic(path: String, bytes: Data) throws {
        let url = baseURL.appendingPathComponent(path)
        let parent = url.deletingLastPathComponent()
        do {
            try fileManager.createDirectory(
                at: parent,
                withIntermediateDirectories: true
            )
            try bytes.write(to: url, options: .atomic)
        } catch {
            throw StorageError.BlobStore("write failed: \(error)")
        }
    }

    public func delete(path: String) throws {
        let url = baseURL.appendingPathComponent(path)
        guard fileManager.fileExists(atPath: url.path) else {
            throw StorageError.BlobStore("delete failed: file not found")
        }
        do {
            try fileManager.removeItem(at: url)
        } catch {
            throw StorageError.BlobStore("delete failed: \(error)")
        }
    }
}
