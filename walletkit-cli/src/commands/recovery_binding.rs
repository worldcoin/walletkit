//! `walletkit recovery-agent` subcommands — recovery agent management.

use clap::Subcommand;

use super::{init_authenticator, Cli};
use crate::output;
use walletkit_core::issuers::RecoveryBindingManager;
use walletkit_core::Environment;
use walletkit_core::UserAgent;

#[derive(Subcommand)]
pub enum RecoveryBindingCommand {
    /// Register bindings for a recovery agent.
    RegisterBindings {
        sub: String,
    },
    UnregisterBindings {
        sub: String,
    },
    GetBinding,
}

pub async fn run(
    cli: &Cli,
    action: &RecoveryBindingCommand,
    environment: &Environment,
) -> eyre::Result<()> {
    let (authenticator, _store) = init_authenticator(cli).await?;

    match action {
        RecoveryBindingCommand::RegisterBindings { sub } => {
            let recovery_agent_address = environment.poh_recovery_agent_address();
            let recovery_binding_manager =
                RecoveryBindingManager::new(environment, UserAgent::default()).unwrap();
            recovery_binding_manager
                .bind_recovery_agent(
                    &authenticator,
                    sub.clone(),
                    recovery_agent_address.clone(),
                )
                .await?;
        }
        RecoveryBindingCommand::UnregisterBindings { sub } => {
            let recovery_binding_manager =
                RecoveryBindingManager::new(environment, UserAgent::default()).unwrap();
            recovery_binding_manager
                .unbind_recovery_agent(&authenticator, sub.clone())
                .await?;
        }
        RecoveryBindingCommand::GetBinding => {
            let recovery_binding_manager =
                RecoveryBindingManager::new(environment, UserAgent::default()).unwrap();
            let recovery_binding = recovery_binding_manager
                .get_recovery_binding(authenticator.leaf_index())
                .await?;
            if cli.json {
                output::print_json_data(
                    &serde_json::json!({
                        "recovery_agent": recovery_binding.recovery_agent,
                        "pending_recovery_agent": recovery_binding.pending_recovery_agent,
                        "execute_after": recovery_binding.execute_after,
                    }),
                    true,
                );
            } else {
                println!("Recovery binding: {recovery_binding:?}");
            }
        }
    }
    Ok(())
}
