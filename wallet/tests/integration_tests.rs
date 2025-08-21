mod common;

use rstest::*;
use wallet::{Wallet, Seed, UnifiedAccount, WalletError};
use common::*;

#[rstest]
#[case(TEST_MNEMONIC_12)]
#[case(TEST_MNEMONIC_24)]
fn test_wallet_from_mnemonic(#[case] mnemonic: &str) {
    let wallet = Wallet::from_mnemonic(mnemonic, None).unwrap();
    assert_eq!(wallet.accounts().len(), 0);
}

#[rstest]
#[case(None)]
#[case(Some("test_passphrase".to_string()))]
fn test_wallet_with_passphrase(#[case] passphrase: Option<String>) {
    let wallet = Wallet::from_mnemonic(TEST_MNEMONIC_12, passphrase).unwrap();
    assert_eq!(wallet.accounts().len(), 0);
}

#[test]
fn test_wallet_account_generation() {
    let seed = create_test_seed().unwrap();
    let mut wallet = Wallet::new(seed);
    
    let account = wallet.generate_account(0, 0).unwrap();
    assert_eq!(account.account_number, 0);
    assert_eq!(account.index, 0);
    assert_eq!(wallet.accounts().len(), 1);
    
    let account2 = wallet.generate_account(0, 1).unwrap();
    assert_eq!(account2.account_number, 0);
    assert_eq!(account2.index, 1);
    assert_eq!(wallet.accounts().len(), 2);
}

#[test]
fn test_wallet_account_retrieval() {
    let seed = create_test_seed().unwrap();
    let mut wallet = Wallet::new(seed);
    
    let _account = wallet.generate_account(0, 5).unwrap();
    
    let retrieved = wallet.get_account(5).unwrap();
    assert_eq!(retrieved.index, 5);
    assert_eq!(retrieved.account_number, 0);
    
    assert!(wallet.get_account(10).is_none());
}

#[test]
fn test_multiple_accounts_different_keys() {
    let seed = create_test_seed().unwrap();
    let mut wallet = Wallet::new(seed);
    
    wallet.generate_account(0, 0).unwrap();
    wallet.generate_account(0, 1).unwrap();
    wallet.generate_account(1, 0).unwrap();
    
    let accounts = wallet.accounts();
    assert_eq!(accounts.len(), 3);
    
    assert_ne!(accounts[0].blockchain_address, accounts[1].blockchain_address);
    assert_ne!(accounts[0].blockchain_address, accounts[2].blockchain_address);
    assert_ne!(accounts[1].blockchain_address, accounts[2].blockchain_address);
    
    assert_ne!(accounts[0].peer_id, accounts[1].peer_id);
    assert_ne!(accounts[0].peer_id, accounts[2].peer_id);
    assert_ne!(accounts[1].peer_id, accounts[2].peer_id);
}

#[test]
fn test_account_key_correlation() {
    let seed = create_test_seed().unwrap();
    
    let account = UnifiedAccount::derive(&seed, 0, 0).unwrap();
    
    assert!(account.blockchain_private_key().is_some());
    assert!(account.blockchain_public_key().is_some());
    assert!(account.p2p_identity().is_some());
    
    let blockchain_private = account.blockchain_private_key().unwrap();
    let blockchain_public = account.blockchain_public_key().unwrap();
    let p2p_identity = account.p2p_identity().unwrap();
    
    assert_ne!(blockchain_private, [0u8; 32]);
    assert_ne!(blockchain_public, [0u8; 33]);
    assert!(!p2p_identity.peer_id_string().is_empty());
}

#[rstest]
#[case(0, 0)]
#[case(0, 1)]
#[case(1, 0)]
#[case(2147483647, 0)] // Max account
#[case(0, 2147483647)] // Max index
fn test_account_derivation_edge_cases(#[case] account_num: u32, #[case] index: u32) {
    let seed = create_test_seed().unwrap();
    let account = UnifiedAccount::derive(&seed, account_num, index);
    
    assert!(account.is_ok());
    let account = account.unwrap();
    assert_eq!(account.account_number, account_num);
    assert_eq!(account.index, index);
}

#[test]
fn test_seed_entropy_validation() {
    assert!(Seed::from_entropy(&TEST_ENTROPY_128).is_ok());
    assert!(Seed::from_entropy(&TEST_ENTROPY_256).is_ok());
    
    let invalid_entropy = [0u8; 15]; // Invalid length
    assert!(Seed::from_entropy(&invalid_entropy).is_err());
}

#[test]
fn test_invalid_mnemonic_handling() {
    let invalid_mnemonics = [
        "",
        "invalid mnemonic phrase",
        "abandon abandon abandon", // Too short
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", // Invalid checksum
    ];
    
    for invalid in &invalid_mnemonics {
        assert!(Wallet::from_mnemonic(invalid, None).is_err());
    }
}

#[test]
fn test_wallet_deterministic_behavior() {
    let wallet1 = Wallet::from_mnemonic(TEST_MNEMONIC_12, None).unwrap();
    let wallet2 = Wallet::from_mnemonic(TEST_MNEMONIC_12, None).unwrap();
    
    let seed1 = create_test_seed().unwrap();
    let seed2 = create_test_seed().unwrap();
    
    let account1_1 = UnifiedAccount::derive(&seed1, 0, 0).unwrap();
    let account1_2 = UnifiedAccount::derive(&seed2, 0, 0).unwrap();
    
    assert_eq!(account1_1.blockchain_address, account1_2.blockchain_address);
    assert_eq!(account1_1.peer_id, account1_2.peer_id);
}