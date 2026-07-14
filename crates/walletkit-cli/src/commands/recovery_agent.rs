//! `walletkit recovery-agent` subcommands — recovery agent management.

use clap::Subcommand;
use eyre::WrapErr as _;

use crate::output;

use super::{init_authenticator, Cli};

#[derive(Subcommand)]
pub enum RecoveryAgentCommand {
    /// Initiate a time-locked recovery agent update (14-day cooldown).
    Initiate {
        /// Checksummed hex address of the new recovery agent (e.g. "0x1234…").
        new_recovery_agent: String,
    },
    /// Execute a pending recovery agent update after the cooldown has elapsed.
    Execute,
    /// Cancel a pending recovery agent update before the cooldown expires.
    Cancel,
}

pub async fn run(cli: &Cli, action: &RecoveryAgentCommand) -> eyre::Result<()> {
    let (authenticator, _store) = init_authenticator(cli).await?;

    match action {
        RecoveryAgentCommand::Initiate { new_recovery_agent } => {
            let request_id = authenticator
                .initiate_recovery_agent_update(new_recovery_agent.clone())
                .await
                .wrap_err("initiate recovery agent update failed")?;

            let data = serde_json::json!({ "request_id": request_id });
            if cli.json {
                output::print_json_data(&data, true);
            } else {
                println!("Recovery agent update initiated. Request ID: {request_id}");
            }
        }
        RecoveryAgentCommand::Execute => {
            let request_id = authenticator
                .execute_recovery_agent_update()
                .await
                .wrap_err("execute recovery agent update failed")?;

            let data = serde_json::json!({ "request_id": request_id });
            if cli.json {
                output::print_json_data(&data, true);
            } else {
                println!("Recovery agent update executed. Request ID: {request_id}");
            }
        }
        RecoveryAgentCommand::Cancel => {
            let request_id = authenticator
                .cancel_recovery_agent_update()
                .await
                .wrap_err("cancel recovery agent update failed")?;

            let data = serde_json::json!({ "request_id": request_id });
            if cli.json {
                output::print_json_data(&data, true);
            } else {
                println!("Recovery agent update cancelled. Request ID: {request_id}");
            }
        }
    }

    Ok(())
}
