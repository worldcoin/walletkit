//! `walletkit recovery-agent` subcommands — recovery agent management.

use clap::Subcommand;

use super::{init_authenticator, Cli};
use walletkit_core::issuers::RecoveryBindingManager;
use walletkit_core::Environment;

#[derive(Subcommand)]
pub enum RecoveryBindingCommand {
    /// Register bindings for a recovery agent.
    RegisterBindings {
        leaf_index: u64,
        sub: String,
    },
    UnregisterBindings {
        leaf_index: u64,
        sub: String,
    },
}

pub async fn run(
    cli: &Cli,
    action: &RecoveryBindingCommand,
    environment: &Environment,
) -> eyre::Result<()> {
    let (authenticator, _store) = init_authenticator(cli).await?;

    match action {
        RecoveryBindingCommand::RegisterBindings { leaf_index, sub } => {
            let recovery_agent_address = environment.poh_recovery_agent_address();
            let recovery_binding_manager =
                RecoveryBindingManager::new(environment).unwrap();
            recovery_binding_manager
                .bind_recovery_agent(
                    &authenticator,
                    *leaf_index,
                    sub.clone(),
                    recovery_agent_address.clone(),
                )
                .await?;
        }
        RecoveryBindingCommand::UnregisterBindings { leaf_index, sub } => {
            let recovery_binding_manager =
                RecoveryBindingManager::new(environment).unwrap();
            recovery_binding_manager
                .unbind_recovery_agent(&authenticator, *leaf_index, sub.clone())
                .await?;
        }
    }
    Ok(())
}
