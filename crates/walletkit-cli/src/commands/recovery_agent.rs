//! `walletkit recovery-agent` subcommands — recovery agent management (WIP-102).

use clap::Subcommand;
use eyre::WrapErr as _;

use crate::output;

use super::{init_authenticator, Cli};

#[derive(Subcommand)]
pub enum RecoveryAgentCommand {
    /// Update the holder's recovery agent. Effective immediately, reversible
    /// during the revert window.
    Update {
        /// Checksummed hex address of the new recovery agent (e.g. "0x1234…").
        new_recovery_agent: String,
    },
    /// Revert an in-flight recovery agent update during the revert window.
    Revert,
}

pub async fn run(cli: &Cli, action: &RecoveryAgentCommand) -> eyre::Result<()> {
    let (authenticator, _store) = init_authenticator(cli).await?;

    match action {
        RecoveryAgentCommand::Update { new_recovery_agent } => {
            let request_id = authenticator
                .update_recovery_agent(new_recovery_agent.clone())
                .await
                .wrap_err("update recovery agent failed")?;

            let data = serde_json::json!({ "request_id": request_id });
            if cli.json {
                output::print_json_data(&data, true);
            } else {
                println!("Recovery agent update submitted. Request ID: {request_id}");
            }
        }
        RecoveryAgentCommand::Revert => {
            let request_id = authenticator
                .revert_recovery_agent_update()
                .await
                .wrap_err("revert recovery agent update failed")?;

            let data = serde_json::json!({ "request_id": request_id });
            if cli.json {
                output::print_json_data(&data, true);
            } else {
                println!("Recovery agent update reverted. Request ID: {request_id}");
            }
        }
    }

    Ok(())
}
