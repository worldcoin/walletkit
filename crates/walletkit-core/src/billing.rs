//! WIP-107 billing state, read from the Billing Contract.
//!
//! The Authenticator decides from this state whether an RP is billed and which billing context to
//! register under (WIP-107 §4.6).

use std::{future::IntoFuture, time::Duration};

use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
};
use web_time::Instant;
use world_id_core::{
    primitives::{billing::BillingContext, rp::RpId},
    FieldElement as CoreFieldElement,
};
use world_id_registries::world_id_billing::WorldIdBilling::{
    self, WorldIdBillingInstance,
};

use crate::{error::WalletKitError, registration::before};

/// How long one Billing Contract read may take.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// A registration the Billing Contract holds for a billing nullifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registration {
    /// The RP the World ID is registered for.
    pub rp_id: RpId,
    /// The start of the period it is registered for.
    pub period_start: u64,
    /// When `register` included it, in Unix seconds.
    pub registered_at: u64,
}

/// Reads one Billing Contract through an RPC provider.
#[derive(Debug, Clone)]
pub struct BillingContract {
    chain_id: U256,
    contract: WorldIdBillingInstance<DynProvider>,
}

impl BillingContract {
    /// Reads the Billing Contract at `address` on chain `chain_id` through `provider`.
    #[must_use]
    pub fn new(provider: DynProvider, chain_id: u64, address: Address) -> Self {
        Self {
            chain_id: U256::from(chain_id),
            contract: WorldIdBilling::new(address, provider),
        }
    }

    /// The billing context of `rp_id` for the period starting at `period_start` on this contract.
    #[must_use]
    pub const fn context(&self, rp_id: RpId, period_start: u64) -> BillingContext {
        BillingContext {
            chain_id: self.chain_id,
            billing_contract: *self.contract.address(),
            rp_id,
            period_start,
        }
    }

    /// Returns whether the Billing Contract bills `rp_id` (`isBilledRp`).
    ///
    /// # Errors
    /// Returns [`WalletKitError::NetworkError`] if the read fails or times out.
    pub async fn is_billed_rp(&self, rp_id: RpId) -> Result<bool, WalletKitError> {
        self.read(
            "isBilledRp",
            self.contract.isBilledRp(rp_id.into_inner()).call(),
        )
        .await
    }

    /// Returns whether `rp_id` has registration capacity left for the period starting at
    /// `period_start` (`getPeriodCapacity`).
    ///
    /// # Errors
    /// Returns [`WalletKitError::NetworkError`] if the read fails or times out.
    pub async fn has_capacity(
        &self,
        rp_id: RpId,
        period_start: u64,
    ) -> Result<bool, WalletKitError> {
        let capacity = self
            .read(
                "getPeriodCapacity",
                self.contract
                    .getPeriodCapacity(rp_id.into_inner(), period_start)
                    .call(),
            )
            .await?;
        Ok(capacity.capacity > capacity.registeredCount)
    }

    /// Returns the registration of `billing_nullifier`, or `None` if it is not registered
    /// (`registrationOf`).
    ///
    /// # Errors
    /// Returns [`WalletKitError::NetworkError`] if the read fails or times out.
    pub async fn registration_of(
        &self,
        billing_nullifier: CoreFieldElement,
    ) -> Result<Option<Registration>, WalletKitError> {
        let registration = self
            .read(
                "registrationOf",
                self.contract
                    .registrationOf(U256::from_be_bytes(
                        billing_nullifier.to_be_bytes(),
                    ))
                    .call(),
            )
            .await?;
        // `registeredAt` is zero for a nullifier that was never registered.
        Ok((registration.registeredAt != 0).then(|| Registration {
            rp_id: RpId::new(registration.rpId),
            period_start: registration.periodStart,
            registered_at: registration.registeredAt,
        }))
    }

    async fn read<T>(
        &self,
        function: &str,
        call: impl IntoFuture<Output = Result<T, alloy::contract::Error>>,
    ) -> Result<T, WalletKitError> {
        let url = format!("{}::{function}", self.contract.address());
        match before(Instant::now() + READ_TIMEOUT, call.into_future()).await {
            Some(Ok(value)) => Ok(value),
            Some(Err(error)) => Err(WalletKitError::NetworkError {
                url,
                error: error.to_string(),
                status: None,
            }),
            None => Err(WalletKitError::NetworkError {
                url,
                error: format!("timed out after {}s", READ_TIMEOUT.as_secs()),
                status: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::providers::{Provider as _, ProviderBuilder};

    use super::*;

    const CONTRACT: Address = Address::repeat_byte(0x0b);

    /// ABI-encodes `words` as consecutive 32-byte big-endian words.
    fn abi_words(words: &[u64]) -> String {
        use std::fmt::Write as _;

        words.iter().fold(String::from("0x"), |mut hex, word| {
            write!(hex, "{word:064x}").expect("writing to a String cannot fail");
            hex
        })
    }

    async fn contract_answering(
        server: &mut mockito::Server,
        result: &str,
    ) -> (BillingContract, mockito::Mock) {
        let mock = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"method":"eth_call"}"#.to_string(),
            ))
            .with_header("content-type", "application/json")
            .with_body(format!(r#"{{"jsonrpc":"2.0","id":0,"result":"{result}"}}"#))
            .create_async()
            .await;
        let provider = ProviderBuilder::new()
            .connect_http(server.url().parse().expect("server url"))
            .erased();
        (BillingContract::new(provider, 480, CONTRACT), mock)
    }

    #[test]
    fn context_names_this_contract_and_chain() {
        let provider = ProviderBuilder::new()
            .connect_http("http://localhost:1".parse().expect("url"))
            .erased();
        let contract = BillingContract::new(provider, 480, CONTRACT);

        assert_eq!(
            contract.context(RpId::new(7), 1_700_000_000),
            BillingContext {
                chain_id: U256::from(480),
                billing_contract: CONTRACT,
                rp_id: RpId::new(7),
                period_start: 1_700_000_000,
            }
        );
    }

    #[tokio::test]
    async fn is_billed_rp_reads_the_allowlist() {
        let mut server = mockito::Server::new_async().await;
        let (contract, mock) = contract_answering(&mut server, &abi_words(&[1])).await;

        assert!(contract.is_billed_rp(RpId::new(7)).await.expect("read"));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn has_capacity_compares_capacity_with_registrations() {
        let mut server = mockito::Server::new_async().await;
        let (contract, _mock) =
            contract_answering(&mut server, &abi_words(&[3, 2])).await;
        assert!(contract
            .has_capacity(RpId::new(7), 100)
            .await
            .expect("read"));

        let mut server = mockito::Server::new_async().await;
        let (contract, _mock) =
            contract_answering(&mut server, &abi_words(&[2, 2])).await;
        assert!(!contract
            .has_capacity(RpId::new(7), 100)
            .await
            .expect("read"));
    }

    #[tokio::test]
    async fn registration_of_reads_registrations() {
        let mut server = mockito::Server::new_async().await;
        let (contract, _mock) =
            contract_answering(&mut server, &abi_words(&[7, 100, 150])).await;
        assert_eq!(
            contract
                .registration_of(CoreFieldElement::from(9u64))
                .await
                .expect("read"),
            Some(Registration {
                rp_id: RpId::new(7),
                period_start: 100,
                registered_at: 150,
            })
        );

        let mut server = mockito::Server::new_async().await;
        let (contract, _mock) =
            contract_answering(&mut server, &abi_words(&[0, 0, 0])).await;
        assert_eq!(
            contract
                .registration_of(CoreFieldElement::from(9u64))
                .await
                .expect("read"),
            None
        );
    }

    #[tokio::test]
    async fn failed_reads_are_network_errors() {
        let server = mockito::Server::new_async().await;
        let url = server.url().parse().expect("server url");
        drop(server);
        let provider = ProviderBuilder::new().connect_http(url).erased();
        let contract = BillingContract::new(provider, 480, CONTRACT);

        let error = contract
            .is_billed_rp(RpId::new(7))
            .await
            .expect_err("the RPC is down");

        assert!(matches!(
            error,
            WalletKitError::NetworkError { url, .. } if url.ends_with("::isBilledRp")
        ));
    }
}
