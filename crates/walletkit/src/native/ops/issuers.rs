//! Credential issuers and recovery bindings.

use crate::native::{codec::Binary, error::Result, operation::Operation};
use std::{collections::HashMap, sync::Arc};
use walletkit_core::{
    authenticator::Authenticator,
    issuers::{RecoveryBinding, RecoveryBindingManager, TfhNfcIssuer},
    user_agent::UserAgentBuilder,
    Credential, Environment,
};
#[cfg(feature = "jni")]
use walletkit_jni_macros::jni_export;

/// `TfhNfcIssuer.create`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn tfh_nfc_issuer_new(
    environment: Environment,
    user_agent: String,
) -> Arc<TfhNfcIssuer> {
    Arc::new(TfhNfcIssuer::new(&environment, user_agent))
}

/// `TfhNfcIssuer.refreshNfcCredential`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn tfh_nfc_issuer_refresh_nfc_credential(
    operation: Operation,
    issuer: Arc<TfhNfcIssuer>,
    request_body: String,
    headers: Binary<HashMap<String, String>>,
) -> Result<Arc<Credential>> {
    operation.run(async move {
        let credential = issuer
            .refresh_nfc_credential(&request_body, headers.0)
            .await?;
        Ok(Arc::new(credential))
    })
}

/// `RecoveryBindingManager.create`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn recovery_binding_manager_new(
    environment: Environment,
    user_agent_builder: Arc<UserAgentBuilder>,
) -> Result<Arc<RecoveryBindingManager>> {
    let manager = RecoveryBindingManager::new(&environment, &user_agent_builder)?;
    Ok(Arc::new(manager))
}

/// `RecoveryBindingManager.newWithBaseUrl`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn recovery_binding_manager_new_with_base_url(
    base_url: String,
    user_agent_builder: Arc<UserAgentBuilder>,
) -> Result<Arc<RecoveryBindingManager>> {
    let manager =
        RecoveryBindingManager::new_with_base_url(&base_url, &user_agent_builder)?;
    Ok(Arc::new(manager))
}

/// `RecoveryBindingManager.bindRecoveryAgent`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn recovery_binding_manager_bind_recovery_agent(
    operation: Operation,
    manager: Arc<RecoveryBindingManager>,
    authenticator: Arc<Authenticator>,
    sub: String,
    recovery_agent_address: String,
) -> Result<()> {
    operation.run(async move {
        Ok(manager
            .bind_recovery_agent(&authenticator, sub, recovery_agent_address)
            .await?)
    })
}

/// `RecoveryBindingManager.unbindRecoveryAgent`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn recovery_binding_manager_unbind_recovery_agent(
    operation: Operation,
    manager: Arc<RecoveryBindingManager>,
    authenticator: Arc<Authenticator>,
    sub: String,
) -> Result<()> {
    operation.run(async move {
        Ok(manager.unbind_recovery_agent(&authenticator, sub).await?)
    })
}

/// `RecoveryBindingManager.getRecoveryBinding`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn recovery_binding_manager_get_recovery_binding(
    operation: Operation,
    manager: Arc<RecoveryBindingManager>,
    leaf_index: u64,
) -> Result<Binary<RecoveryBinding>> {
    operation
        .run(async move { Ok(Binary(manager.get_recovery_binding(leaf_index).await?)) })
}
