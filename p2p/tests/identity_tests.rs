use p2p::P2PNode;
use wallet::Wallet;

mod common;

#[test]
fn test_p2p_node_creation() {
    let node = common::create_test_node();
    assert!(node.is_ok());
}

#[test]
fn test_deterministic_peer_id() {
    let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet1 = Wallet::from_mnemonic(test_mnemonic, None).unwrap();
    let mut wallet2 = Wallet::from_mnemonic(test_mnemonic, None).unwrap();
    
    let account1 = wallet1.generate_account(0, 0).unwrap();
    let account2 = wallet2.generate_account(0, 0).unwrap();
    
    let key1 = account1.ed25519_derived_key().unwrap();
    let key2 = account2.ed25519_derived_key().unwrap();
    
    let node1 = P2PNode::from_wallet_key(key1).unwrap();
    let node2 = P2PNode::from_wallet_key(key2).unwrap();
    
    assert_eq!(node1.peer_id(), node2.peer_id());
}

#[test]
fn test_different_accounts_different_peer_ids() {
    let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet1 = Wallet::from_mnemonic(test_mnemonic, None).unwrap();
    let mut wallet2 = Wallet::from_mnemonic(test_mnemonic, None).unwrap();
    
    let account1 = wallet1.generate_account(0, 0).unwrap();
    let account2 = wallet2.generate_account(0, 1).unwrap();
    
    let key1 = account1.ed25519_derived_key().unwrap();
    let key2 = account2.ed25519_derived_key().unwrap();
    
    let node1 = P2PNode::from_wallet_key(key1).unwrap();
    let node2 = P2PNode::from_wallet_key(key2).unwrap();
    
    assert_ne!(node1.peer_id(), node2.peer_id());
}

#[test]
fn test_peer_id_format() {
    let node = common::create_test_node().unwrap();
    let peer_id_str = node.peer_id().to_string();
    
    assert!(peer_id_str.starts_with("12D3KooW"));
    assert!(peer_id_str.len() > 50);
}