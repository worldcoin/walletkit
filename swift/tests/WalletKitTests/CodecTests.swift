import Foundation
import XCTest

@testable import WalletKit

/// Frozen encodings shared with `crates/walletkit/src/native/values.rs`.
final class CodecTests: XCTestCase {
  private func bytes(_ hex: String) -> Data {
    var data = Data()
    var index = hex.startIndex
    while index < hex.endIndex {
      let next = hex.index(index, offsetBy: 2)
      data.append(UInt8(hex[index..<next], radix: 16)!)
      index = next
    }
    return data
  }
  private func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

  func testActivityListDecodes() throws {
    let entries = try ByteReader.decode(
      bytes(
        "02000000010100000000000000ffffffffffffffff030000006170700a0000007a61c5bcc3b3c582c487"
          + "0101640000000000000003020000000700000000000000ffffffffffffffff0104000200000000000000"
          + "0000000001000000630000000000000000")
    ) { try $0.list(ActivityEntry.read) }
    XCTAssertEqual(entries.count, 2)
    XCTAssertEqual(entries[0].id, 1)
    XCTAssertEqual(entries[0].rpId, UInt64.max)
    XCTAssertEqual(entries[0].clientId, "zażółć")
    XCTAssertEqual(entries[0].protocol, .v4)
    XCTAssertEqual(entries[0].outcome, .failed)
    XCTAssertEqual(entries[0].issuerSchemaIds, [7, UInt64.max])
    XCTAssertEqual(entries[0].failureReason, .relyingPartyRejected)
    XCTAssertNil(entries[1].id)
    XCTAssertEqual(entries[1].appIdentifier, "")
    XCTAssertNil(entries[1].timestamp)
    XCTAssertEqual(entries[1].outcome, .completed)
  }

  func testRecordsDecode() throws {
    let records = try ByteReader.decode(
      bytes("010000000100000000000000ffffffffffffffff0300000000000000040000000000000001")
    ) { try $0.list(CredentialRecord.read) }
    XCTAssertEqual(records.map(\.issuerSchemaId), [UInt64.max])
    XCTAssertEqual(records.map(\.isExpired), [true])

    let check = try ByteReader.decode(bytes("0001000000030000006f7262090000000000000001")) {
      try CredentialConstraintsCheckResult.read(&$0)
    }
    XCTAssertFalse(check.isSatisfied)
    XCTAssertEqual(check.checkResults.map(\.identifier), ["orb"])

    let data = try ByteReader.decode(bytes("0300000030786102000000706b0100000063")) {
      try RecoveryData.read(&$0)
    }
    XCTAssertEqual(
      [data.authenticatorAddress, data.authenticatorPubkey, data.offchainSignerCommitment],
      ["0xa", "pk", "c"])

    let signature = try ByteReader.decode(
      bytes("03000000010203000000000000000000000000000000000000000000000000000000000000002a")
    ) { try RecoveryUpdateSignature.read(&$0) }
    XCTAssertEqual(signature.signature, Data([1, 2, 3]))
    XCTAssertEqual(signature.nonce, try Uint256(hex: "2a"))

    let binding = try ByteReader.decode(bytes("01010000006100010100000074")) {
      try RecoveryBinding.read(&$0)
    }
    XCTAssertEqual(binding.recoveryAgent, "a")
    XCTAssertNil(binding.pendingRecoveryAgent)
    XCTAssertEqual(binding.executeAfter, "t")

    XCTAssertEqual(
      try ByteReader.decode(bytes("0200000001010000006100")) {
        try $0.list { try $0.optional { try $0.string() } }
      }, ["a", nil])
    XCTAssertEqual(
      try ByteReader.decode(bytes("010000000400000030783031")) { try $0.list { try $0.string() } },
      ["0x01"])
  }

  func testStatusesAndOutcomesDecode() throws {
    guard
      case .submitted("0x1") = try ByteReader.decode(bytes("0203000000307831"), {
        try GatewayRequestStatus.read(&$0)
      }),
      case .failed("e", "c") = try ByteReader.decode(bytes("040100000065010100000063"), {
        try GatewayRequestStatus.read(&$0)
      }),
      case .finalized = try ByteReader.decode(bytes("03"), { try RegistrationStatus.read(&$0) }),
      case .failed("e", nil) = try ByteReader.decode(bytes("04010000006500"), {
        try RegistrationStatus.read(&$0)
      }),
      case .rejected(
        .imageRejected(.liveSelfie, .noisyThermalImage, .lightGuardPair), .omittedTooLarge(5)) =
        try ByteReader.decode(bytes("0106012a0103020500000000000000"), {
          try FlamingoMatchOutcome.read(&$0)
        }),
      case .rejected(.inputRejected(.totalImagesTooLarge, nil, 10), .available("{}")) =
        try ByteReader.decode(bytes("01040500010a0000000000000000020000007b7d"), {
          try FlamingoMatchOutcome.read(&$0)
        })
    else { return XCTFail("unexpected decoding") }
  }

  func testErrorsDecodeIntoTypedErrors() throws {
    XCTAssertTrue(
      try decodeNativeError(bytes("000900000043616e63656c6c6564")) is CancellationError)
    guard
      case WalletKitError.networkError("u", "e", 503) = try decodeNativeError(
        bytes("01040100000075010000006501f701")),
      case WalletKitError.storage(.invalidLeafIndex(1, 2)) = try decodeNativeError(
        bytes("01000b01000000000000000200000000000000")),
      case StorageError.keystore("denied") = try decodeNativeError(
        bytes("02000600000064656e696564")),
      case FlamingoError.invalidInput("a", "r", .tooLarge, 9) = try decodeNativeError(
        bytes("03000100000061010000007201010900000000000000")),
      case FlamingoError.requestIntegrity(.timedOut) = try decodeNativeError(bytes("030204")),
      case CredentialConstraintsCheckError.constraintTooDeep = try decodeNativeError(
        bytes("0401"))
    else { return XCTFail("unexpected error decoding") }
  }

  func testInputsEncodeToFrozenBytes() throws {
    let entry = ActivityEntry(
      id: 1, rpId: UInt64.max, appIdentifier: "app", clientId: "zażółć", protocol: .v4,
      timestamp: 100, outcome: .failed, issuerSchemaIds: [7, UInt64.max],
      failureReason: .relyingPartyRejected)
    XCTAssertEqual(
      hex(ByteWriter.encode { entry.write(&$0) }),
      "010100000000000000ffffffffffffffff030000006170700a0000007a61c5bcc3b3c582c4870101640000"
        + "000000000003020000000700000000000000ffffffffffffffff0104")
    XCTAssertEqual(
      hex(ByteWriter.encode { writeStringMap(["k": "v"], &$0) }), "01000000010000006b0100000076")
    XCTAssertEqual(
      hex(ByteWriter.encode { writeMeasurements([2: Data([0xab])], &$0) }),
      "010000000200000001000000ab")
    let deepFace = FlamingoMatchRequest.deepFace(
      orbCredential: Data([1]),
      live: .lightGuard(
        illuminated: Data([2]), unilluminated: Data([3]), matchingFrame: .unilluminated),
      rtmsChallenge: Data([4]), hashesJson: Data("{}".utf8), matchThreshold: 0.5)
    XCTAssertEqual(
      hex(ByteWriter.encode { deepFace.write(&$0) }),
      "0001000000010101000000020100000003010100000004020000007b7d000000000000e03f")
    let grayBadge = FlamingoMatchRequest.grayBadge(
      live: .vanilla(image: Data([5])), rtmsChallenge: Data(), matchThreshold: 1)
    XCTAssertEqual(
      hex(ByteWriter.encode { grayBadge.write(&$0) }), "0100010000000500000000000000000000f03f")
    XCTAssertEqual(
      hex(ByteWriter.encode { StorageError.keystore(value0: "denied").write(&$0) }),
      "000600000064656e696564")
  }

  func testMalformedResultsAreRejected() {
    for bad in ["", "0300000030786102000000706b010000006300", "02ffffff", "0400000000"] {
      XCTAssertThrowsError(try ByteReader.decode(bytes(bad)) { try RecoveryData.read(&$0) })
    }
    XCTAssertThrowsError(try ByteReader.decode(bytes("05")) { try GatewayRequestStatus.read(&$0) })
    XCTAssertThrowsError(try ByteReader.decode(bytes("02")) { try $0.bool() })
  }

  func testHandlesFromAFailedDecodeAreReleased() throws {
    let field = try FieldElement.fromU64(value: 5)
    let id = try field.handle.withID { $0 }
    var truncated = ByteWriter()
    truncated.u32(1)
    truncated.u64(id)
    XCTAssertThrowsError(
      try ByteReader.decode(truncated.data) { reader -> [FieldElement] in
        let elements = try reader.list { FieldElement(handle: try $0.handle()) }
        _ = try reader.u8()
        return elements
      })
    XCTAssertThrowsError(try field.toHexString()) { error in
      XCTAssertEqual((error as? WalletKitBridgeError)?.code, "InvalidHandle")
    }
  }
}
