# Integration Tests

These tests are used to verify the correct functionality of the World ID SDK beyond the basic Rust interactions.

### Test scenarios

- Solidity compatibility. Key functionality is tested against the Solidity implementation.

### Updating the Solidity contracts

When updating the Solidity contracts, make sure to run `forge` to rebuild the JSON artifacts.

```bash
forge build -C walletkit-core/tests/contracts -o walletkit-core/tests/out
```
