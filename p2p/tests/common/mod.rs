use wallet::{Seed, UnifiedAccount};
use p2p::{P2PNode, P2PError};

pub mod integration;

pub fn create_test_account() -> Result<UnifiedAccount, P2PError> {
    let seed = Seed::generate(12)?;
    let account = UnifiedAccount::derive(&seed, 0, 0)?;
    Ok(account)
}

pub fn create_test_node() -> Result<P2PNode, P2PError> {
    let account = create_test_account()?;
    let ed25519_key = account.ed25519_derived_key()
        .ok_or_else(|| P2PError::Identity("No ed25519 key".to_string()))?;
    P2PNode::from_wallet_key(ed25519_key)
}

