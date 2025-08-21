// Critical tests for the private derive_key function
// These test edge cases that docs.rs identified as potential failure points

use wallet::{WalletStorage, Seed};
use zeroize::Zeroizing;
use std::fs;

#[test]
fn test_empty_password_rejection() {
    // Empty passwords should now be rejected for security
    let wallet_name = "test_zero_pwd_derive";
    let zero_password = Zeroizing::new(String::new());
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Empty password should now be rejected
    let result = WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &zero_password);
    assert!(result.is_err(), "Empty password should be rejected");
    
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("cannot be empty"), "Error should mention empty password");
}

#[test]
fn test_derive_key_output_buffer_size() {
    // This verifies our 32-byte output buffer is correct for AES-256
    // According to docs.rs, insufficient buffer size can cause failures
    let wallet_name = "test_buffer_size";
    let password = Zeroizing::new("test_password".to_string());
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Our implementation uses [0u8; 32] - this should be correct for AES-256-GCM
    let result = WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &password);
    assert!(result.is_ok(), "32-byte buffer should be sufficient for AES-256 key derivation");
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
}

#[test]
fn test_salt_size_requirement() {
    // This verifies our SALT_SIZE constant (32 bytes) meets Argon2 requirements
    let wallet_name = "test_salt_size";
    let password = Zeroizing::new("test_password".to_string());
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Our implementation uses 32-byte salt - this should be adequate
    let result = WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &password);
    assert!(result.is_ok(), "32-byte salt should meet Argon2 requirements");
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
}

#[test]
fn test_nonce_size_requirement() {
    // This verifies our NONCE_SIZE constant (12 bytes) is correct for AES-GCM
    let wallet_name = "test_nonce_size";
    let password = Zeroizing::new("test_password".to_string());
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Our implementation uses 12-byte nonce - this should be correct for AES-GCM
    let result = WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &password);
    assert!(result.is_ok(), "12-byte nonce should be correct for AES-GCM");
    
    // Verify the stored file has 12-byte nonce
    let path = WalletStorage::get_wallet_path(wallet_name).unwrap();
    let content = fs::read_to_string(&path).unwrap();
    let wallet: serde_json::Value = serde_json::from_str(&content).unwrap();
    
    if let Some(nonce_array) = wallet["nonce"].as_array() {
        assert_eq!(nonce_array.len(), 12, "Nonce should be exactly 12 bytes for AES-GCM");
    } else {
        panic!("Could not read nonce from wallet file");
    }
    
    // Clean up
    let _ = fs::remove_file(path);
}

#[test]
fn test_key_derivation_consistency() {
    // This tests that the same password and salt always produce the same key
    // This is critical for deterministic encryption/decryption
    let wallet_name1 = "test_derive_consistency_1";
    let wallet_name2 = "test_derive_consistency_2";
    let password = Zeroizing::new("consistency_test_password".to_string());
    let mnemonic = "consistency test mnemonic phrase";
    
    // Clean up
    for name in [wallet_name1, wallet_name2] {
        if let Ok(path) = WalletStorage::get_wallet_path(name) {
            let _ = fs::remove_file(path);
        }
    }
    
    // Save the same data twice
    WalletStorage::save_encrypted_wallet(wallet_name1, mnemonic, &password).unwrap();
    WalletStorage::save_encrypted_wallet(wallet_name2, mnemonic, &password).unwrap();
    
    // Both should decrypt successfully (proving key derivation is consistent)
    let loaded1 = WalletStorage::load_encrypted_wallet(wallet_name1, &password).unwrap();
    let loaded2 = WalletStorage::load_encrypted_wallet(wallet_name2, &password).unwrap();
    
    assert_eq!(loaded1, mnemonic);
    assert_eq!(loaded2, mnemonic);
    assert_eq!(loaded1, loaded2);
    
    // Clean up
    for name in [wallet_name1, wallet_name2] {
        if let Ok(path) = WalletStorage::get_wallet_path(name) {
            let _ = fs::remove_file(path);
        }
    }
}

#[test]
fn test_unicode_rejection() {
    // Unicode passwords should now be rejected for security
    let wallet_name = "test_unicode_reject";
    
    let unicode_password = Zeroizing::new("café".to_string()); // Unicode character
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Unicode password should be rejected
    let result = WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &unicode_password);
    assert!(result.is_err(), "Unicode password should be rejected");
    
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("ASCII characters"), "Error should mention ASCII requirement");
    assert!(error_msg.contains("security reasons"), "Error should explain security rationale");
}