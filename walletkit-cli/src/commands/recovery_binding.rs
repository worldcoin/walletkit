//! `walletkit recovery-agent` subcommands — recovery agent management.

use clap::Subcommand;

use super::{init_authenticator, Cli};
use walletkit_core::issuers::RecoveryBindingManager;
use walletkit_core::Environment;

#[derive(Subcommand)]
pub enum RecoveryBindingCommand {
    /// Register bindings for a recovery agent.
    RegisterBindings {
        /// Checksummed hex address of the recovery agent (e.g. "0x1234…").
        sub: String,
    },
    UnregisterBindings {
        sub: String,
    },
}

pub async fn run(cli: &Cli, action: &RecoveryBindingCommand) -> eyre::Result<()> {
    let (authenticator, _store) = init_authenticator(cli).await?;
    let leaf_index = authenticator.leaf_index();

    match action {
        RecoveryBindingCommand::RegisterBindings { sub } => {
            let recovery_agent_address =
                Environment::Staging.poh_recovery_agent_address();
            let recovery_binding_manager =
                RecoveryBindingManager::new(&Environment::Staging).unwrap();
            recovery_binding_manager
                .bind_recovery_agent(
                    &authenticator,
                    leaf_index,
                    sub.clone(),
                    recovery_agent_address.clone(),
                )
                .await?;
        }
        RecoveryBindingCommand::UnregisterBindings { sub } => {
            let recovery_binding_manager =
                RecoveryBindingManager::new(&Environment::Staging).unwrap();
            recovery_binding_manager
                .unbind_recovery_agent(&authenticator, leaf_index, sub.clone())
                .await?;
        }
    }
    Ok(())
}
