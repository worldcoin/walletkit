/// Contains all components to interact and use a World ID
pub mod world_id;

/// This module handles World ID proof generation
pub mod proof;

/// This module exposes helper functions to interact with common apps & contracts related to the World ID Protocol.
pub mod common_apps;

mod credential_type;
pub use credential_type::CredentialType;

////////////////////////////////////////////////////////////////////////////////
// Private modules
////////////////////////////////////////////////////////////////////////////////

mod merkle_tree;
