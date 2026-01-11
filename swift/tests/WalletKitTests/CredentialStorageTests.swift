import XCTest
import Foundation

@testable import WalletKit

final class CredentialStorageTests: XCTestCase {
    
    var tempDirectory: String!
    
    override func setUp() {
        super.setUp()
        // Create a temporary directory for each test
        tempDirectory = NSTemporaryDirectory() + UUID().uuidString
        try? FileManager.default.createDirectory(
            atPath: tempDirectory,
            withIntermediateDirectories: true,
            attributes: nil
        )
    }
    
    override func tearDown() {
        // Clean up temporary directory
        try? FileManager.default.removeItem(atPath: tempDirectory)
        super.tearDown()
    }
    
    // MARK: - Store Creation Tests
    
    func testStoreCreation() throws {
        // Test creating a WorldIdStore instance
        let store = try WorldIdStore(rootPath: tempDirectory)
        XCTAssertNotNil(store)
    }
    
    func testListAccountsEmpty() throws {
        // Test that a new store has no accounts
        let store = try WorldIdStore(rootPath: tempDirectory)
        let accounts = try store.listAccounts()
        XCTAssertTrue(accounts.isEmpty, "New store should have no accounts")
    }
    
    // MARK: - Account Creation Tests
    
    func testCreateAccount() throws {
        // Test creating a new account
        let store = try WorldIdStore(rootPath: tempDirectory)
        let handle = try store.createAccount()
        XCTAssertNotNil(handle)
        
        // Verify account is listed
        let accounts = try store.listAccounts()
        XCTAssertEqual(accounts.count, 1, "Should have exactly one account")
    }
    
    func testAccountId() throws {
        // Test that account ID is valid hex string
        let store = try WorldIdStore(rootPath: tempDirectory)
        let handle = try store.createAccount()
        let accountId = handle.accountId()
        
        XCTAssertFalse(accountId.hex.isEmpty, "Account ID should not be empty")
        XCTAssertEqual(accountId.hex.count, 64, "Account ID should be 32 bytes (64 hex chars)")
    }
    
    func testMultipleAccounts() throws {
        // Test creating multiple accounts
        let store = try WorldIdStore(rootPath: tempDirectory)
        
        let handle1 = try store.createAccount()
        let handle2 = try store.createAccount()
        
        let id1 = handle1.accountId()
        let id2 = handle2.accountId()
        
        // Account IDs should be unique
        XCTAssertNotEqual(id1.hex, id2.hex, "Account IDs should be unique")
        
        // Should have 2 accounts listed
        let accounts = try store.listAccounts()
        XCTAssertEqual(accounts.count, 2, "Should have exactly two accounts")
    }
    
    // MARK: - Credential ID Generation Tests
    
    func testGenerateCredentialId() throws {
        let credId1 = generateCredentialId()
        let credId2 = generateCredentialId()
        
        // IDs should be non-empty
        XCTAssertFalse(credId1.hex.isEmpty)
        XCTAssertFalse(credId2.hex.isEmpty)
        
        // IDs should be unique
        XCTAssertNotEqual(credId1.hex, credId2.hex, "Generated credential IDs should be unique")
        
        // IDs should be 16 bytes (32 hex chars)
        XCTAssertEqual(credId1.hex.count, 32, "Credential ID should be 16 bytes (32 hex chars)")
    }
    
    // MARK: - Device Key Pair Tests
    
    func testGenerateDeviceKeyPair() throws {
        let keyPair = generateDeviceKeyPair()
        
        // Public key should be 32 bytes (X25519)
        XCTAssertEqual(keyPair.publicKey.count, 32, "Public key should be 32 bytes")
        
        // Secret key should be 32 bytes (X25519)
        XCTAssertEqual(keyPair.secretKey.count, 32, "Secret key should be 32 bytes")
    }
    
    func testDeviceKeyPairUniqueness() throws {
        let keyPair1 = generateDeviceKeyPair()
        let keyPair2 = generateDeviceKeyPair()
        
        // Key pairs should be unique
        XCTAssertNotEqual(keyPair1.publicKey, keyPair2.publicKey, "Public keys should be unique")
        XCTAssertNotEqual(keyPair1.secretKey, keyPair2.secretKey, "Secret keys should be unique")
    }
    
    // MARK: - Credential Storage Tests
    
    func testStoreAndGetCredential() throws {
        let store = try WorldIdStore(rootPath: tempDirectory)
        let handle = try store.createAccount()
        
        // Generate a credential ID
        let credentialId = generateCredentialId()
        
        // Create test credential data
        let credentialBlob = Data("test credential data".utf8)
        let associatedData = Data("test associated data".utf8)
        
        // Store the credential
        try handle.storeCredential(
            credentialId: credentialId,
            credentialBlob: credentialBlob,
            associatedData: associatedData
        )
        
        // Retrieve the credential
        let retrieved = try handle.getCredential(credentialId: credentialId)
        
        XCTAssertEqual(retrieved.credentialBlob, credentialBlob)
        XCTAssertEqual(retrieved.associatedData, associatedData)
    }
    
    func testListCredentials() throws {
        let store = try WorldIdStore(rootPath: tempDirectory)
        let handle = try store.createAccount()
        
        // Initially should have no credentials
        let initialCreds = try handle.listCredentials(filter: CredentialFilter(
            issuerSchemaId: nil,
            status: nil,
            includeExpired: false
        ))
        XCTAssertTrue(initialCreds.isEmpty)
        
        // Store a credential
        let credentialId = generateCredentialId()
        try handle.storeCredential(
            credentialId: credentialId,
            credentialBlob: Data("test".utf8),
            associatedData: nil
        )
        
        // Should now have one credential
        let creds = try handle.listCredentials(filter: CredentialFilter(
            issuerSchemaId: nil,
            status: nil,
            includeExpired: false
        ))
        XCTAssertEqual(creds.count, 1)
    }
    
    // MARK: - Error Handling Tests
    
    func testGetNonexistentCredential() throws {
        let store = try WorldIdStore(rootPath: tempDirectory)
        let handle = try store.createAccount()
        
        let nonexistentId = generateCredentialId()
        
        // Should throw an error for non-existent credential
        XCTAssertThrowsError(try handle.getCredential(credentialId: nonexistentId)) { error in
            XCTAssertNotNil(error, "Should throw error for non-existent credential")
        }
    }
    
    // MARK: - Persistence Tests
    
    func testAccountPersistence() throws {
        var accountIdHex: String
        
        // Create store and account in first scope
        do {
            let store = try WorldIdStore(rootPath: tempDirectory)
            let handle = try store.createAccount()
            accountIdHex = handle.accountId().hex
        }
        
        // Reopen store and verify account exists
        do {
            let store = try WorldIdStore(rootPath: tempDirectory)
            let accounts = try store.listAccounts()
            XCTAssertEqual(accounts.count, 1)
            XCTAssertEqual(accounts.first?.hex, accountIdHex)
        }
    }
    
    // MARK: - Key Derivation Tests
    
    func testDeriveIssuerBlind() throws {
        let store = try WorldIdStore(rootPath: tempDirectory)
        let handle = try store.createAccount()
        
        // Derive issuer blind for schema ID 42
        let blind1 = handle.deriveIssuerBlind(issuerSchemaId: 42)
        let blind2 = handle.deriveIssuerBlind(issuerSchemaId: 42)
        
        // Same schema ID should give same blind (deterministic)
        XCTAssertEqual(blind1, blind2, "Issuer blind should be deterministic")
        
        // Different schema ID should give different blind
        let blind3 = handle.deriveIssuerBlind(issuerSchemaId: 43)
        XCTAssertNotEqual(blind1, blind3, "Different schema IDs should give different blinds")
    }
    
    func testDeriveSessionR() throws {
        let store = try WorldIdStore(rootPath: tempDirectory)
        let handle = try store.createAccount()
        
        // Create 32-byte RP ID and action ID
        let rpId = Data(repeating: 0x01, count: 32)
        let actionId = Data(repeating: 0x02, count: 32)
        
        // Derive session randomness
        let r1 = try handle.deriveSessionR(rpId: rpId, actionId: actionId)
        let r2 = try handle.deriveSessionR(rpId: rpId, actionId: actionId)
        
        // Same inputs should give same output (deterministic)
        XCTAssertEqual(r1, r2, "Session R should be deterministic")
        
        // Different inputs should give different output
        let differentActionId = Data(repeating: 0x03, count: 32)
        let r3 = try handle.deriveSessionR(rpId: rpId, actionId: differentActionId)
        XCTAssertNotEqual(r1, r3, "Different action IDs should give different session R")
    }
}
