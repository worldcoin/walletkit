// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// make sure to run `forge build -C walletkit-core/tests/contracts -o walletkit-core/tests/out` when updating

library ByteHasher {
    /// @dev Creates a keccak256 hash of a bytestring.
    /// @param value The bytestring to hash
    /// @return The hash of the specified value
    /// @dev `>> 8` makes sure that the result is included in our field
    function hashToField(bytes memory value) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(value))) >> 8;
    }
}

/// @title ExternalNullifier
/// @author World
/// @notice A contract to test external nullifier generation. REMINDER TO UPDATE THE JSON ARTIFACTS WHEN UPDATING THIS CONTRACT.
contract ExternalNullifier {
    using ByteHasher for bytes;

    string appId;

    /// @notice Constructs the contract
    constructor(string memory _appId) {
        appId = _appId;
    }

    /// @notice Generate an external nullifier to be used in tests
    /// @param someText A random string to be included
    /// @return The external nullifier
    function generateExternalNullifier(string memory someText) external view returns (uint256) {
        uint256 externalNullifier = abi.encodePacked(
                abi.encodePacked(appId).hashToField(),
                abi.encodePacked(msg.sender), // Note how this could be used to validate a more advanced context
                abi.encodePacked(someText)
            ).hashToField();

        return externalNullifier;
    }
}
