// Comprehensive edge case tests for encryption components
// Based on docs.rs analysis of potential failure modes

use wallet::{WalletStorage, Seed};
use zeroize::Zeroizing;
use std::fs;
use base64::{Engine as _, engine::general_purpose};

#[test]
fn test_nonce_uniqueness_across_encryptions() {
    // Critical test: AES-GCM nonces MUST be unique to prevent catastrophic failure
    let password = Zeroizing::new("test_password".to_string());
    let mnemonic = "test mnemonic for nonce uniqueness";
    
    let wallet_names = [
        "nonce_test_1", "nonce_test_2", "nonce_test_3", 
        "nonce_test_4", "nonce_test_5"
    ];
    
    // Clean up
    for name in &wallet_names {
        if let Ok(path) = WalletStorage::get_wallet_path(name) {
            let _ = fs::remove_file(path);
        }
    }
    
    // Save multiple wallets with same password and mnemonic
    for name in &wallet_names {
        WalletStorage::save_encrypted_wallet(name, mnemonic, &password).unwrap();
    }
    
    // Extract nonces from all encrypted files
    let mut nonces = Vec::new();
    for name in &wallet_names {
        let path = WalletStorage::get_wallet_path(name).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        let wallet: serde_json::Value = serde_json::from_str(&content).unwrap();
        if let Some(nonce_array) = wallet["nonce"].as_array() {
            // Handle nonce as array of bytes
            let nonce_bytes: Vec<u8> = nonce_array.iter()
                .map(|v| v.as_u64().unwrap() as u8)
                .collect();
            let nonce_b64 = general_purpose::STANDARD.encode(&nonce_bytes);
            nonces.push(nonce_b64);
        } else {
            panic!("Unexpected nonce format in wallet file");
        }
    }
    
    // All nonces MUST be different (this is critical for AES-GCM security)
    assert_eq!(nonces.len(), 5);
    for i in 0..nonces.len() {
        for j in (i+1)..nonces.len() {
            assert_ne!(nonces[i], nonces[j], 
                "Nonce collision detected between {} and {}: this is a critical security vulnerability!", 
                wallet_names[i], wallet_names[j]);
        }
    }
    
    // Clean up
    for name in &wallet_names {
        if let Ok(path) = WalletStorage::get_wallet_path(name) {
            let _ = fs::remove_file(path);
        }
    }
}

#[test]
fn test_concurrent_wallet_creation() {
    // Test that concurrent wallet creation doesn't cause collisions
    use std::thread;
    
    let wallet_base = "concurrent_test";
    let password = Zeroizing::new("test_password".to_string());
    let mnemonic = "concurrent test mnemonic";
    
    // Clean up any existing wallets
    for i in 0..10 {
        let name = format!("{}_{}", wallet_base, i);
        if let Ok(path) = WalletStorage::get_wallet_path(&name) {
            let _ = fs::remove_file(path);
        }
    }
    
    // Create wallets concurrently
    let handles: Vec<_> = (0..10).map(|i| {
        let name = format!("{}_{}", wallet_base, i);
        let password = password.clone();
        let mnemonic = mnemonic.to_string();
        
        thread::spawn(move || {
            WalletStorage::save_encrypted_wallet(&name, &mnemonic, &password)
        })
    }).collect();
    
    // Wait for all threads and check results
    for (i, handle) in handles.into_iter().enumerate() {
        let result = handle.join().unwrap();
        assert!(result.is_ok(), "Concurrent wallet creation {} failed", i);
    }
    
    // Verify all wallets exist and have unique content
    let mut contents = Vec::new();
    for i in 0..10 {
        let name = format!("{}_{}", wallet_base, i);
        assert!(WalletStorage::wallet_exists(&name));
        
        let path = WalletStorage::get_wallet_path(&name).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        contents.push(content);
    }
    
    // All encrypted contents should be different (different nonces/salts)
    for i in 0..contents.len() {
        for j in (i+1)..contents.len() {
            assert_ne!(contents[i], contents[j], 
                "Duplicate wallet content detected: concurrent creation collision");
        }
    }
    
    // Clean up
    for i in 0..10 {
        let name = format!("{}_{}", wallet_base, i);
        if let Ok(path) = WalletStorage::get_wallet_path(&name) {
            let _ = fs::remove_file(path);
        }
    }
}

#[test]
fn test_max_password_length_boundary() {
    // Test Argon2 password length limits (512 bytes max according to docs)
    let wallet_name = "max_password_test";
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Test exactly 512 bytes (Argon2 maximum)
    let max_password = Zeroizing::new("a".repeat(512));
    let result = WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &max_password);
    
    // This should work at the boundary
    assert!(result.is_ok(), "Failed to handle 512-byte password (Argon2 max)");
    
    // Verify it can be loaded
    let loaded = WalletStorage::load_encrypted_wallet(wallet_name, &max_password).unwrap();
    assert_eq!(loaded, mnemonic);
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
}

#[test] 
fn test_binary_data_in_passwords() {
    // Test passwords containing binary/non-UTF8 data
    let wallet_name = "binary_password_test";
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Create password with special characters and control characters  
    let binary_password = Zeroizing::new(
        format!("pass{}word{}{}{}\t\n\r{}", 
            '\0', '\x01', '\x02', '\x03', '\x7f')
    );
    
    let result = WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &binary_password);
    assert!(result.is_ok(), "Failed to handle password with binary data");
    
    let loaded = WalletStorage::load_encrypted_wallet(wallet_name, &binary_password).unwrap();
    assert_eq!(loaded, mnemonic);
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
}

#[test]
fn test_encryption_with_all_zero_salt() {
    // Verify that our salt generation never produces all zeros
    let password = Zeroizing::new("test_password".to_string());
    let mnemonic = "test mnemonic";
    
    let wallet_names: Vec<String> = (0..50).map(|i| format!("salt_zero_test_{}", i)).collect();
    
    // Clean up
    for name in &wallet_names {
        if let Ok(path) = WalletStorage::get_wallet_path(name) {
            let _ = fs::remove_file(path);
        }
    }
    
    // Create many wallets to check salt randomness
    for name in &wallet_names {
        WalletStorage::save_encrypted_wallet(name, mnemonic, &password).unwrap();
    }
    
    // Check that no salt is all zeros (base64 encoded)
    let all_zero_salt_b64 = general_purpose::STANDARD.encode([0u8; 32]);
    
    for name in &wallet_names {
        let path = WalletStorage::get_wallet_path(name).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        let wallet: serde_json::Value = serde_json::from_str(&content).unwrap();
        
        if let Some(salt_array) = wallet["salt"].as_array() {
            // Handle salt as array of bytes
            let salt_bytes: Vec<u8> = salt_array.iter()
                .map(|v| v.as_u64().unwrap() as u8)
                .collect();
            let salt_b64 = general_purpose::STANDARD.encode(&salt_bytes);
            
            assert_ne!(salt_b64, all_zero_salt_b64, 
                "All-zero salt detected in wallet {}: this indicates weak randomness", name);
        } else {
            panic!("Unexpected salt format in wallet file");
        }
    }
    
    // Clean up
    for name in &wallet_names {
        if let Ok(path) = WalletStorage::get_wallet_path(name) {
            let _ = fs::remove_file(path);
        }
    }
}

#[test]
fn test_malformed_ciphertext_attack() {
    // Test that malformed ciphertext is properly rejected
    let wallet_name = "malformed_ciphertext_test";
    let password = Zeroizing::new("test_password".to_string());
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Save wallet normally
    WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &password).unwrap();
    
    let wallet_path = WalletStorage::get_wallet_path(wallet_name).unwrap();
    
    // Read and parse the wallet
    let content = fs::read_to_string(&wallet_path).unwrap();
    let mut wallet: serde_json::Value = serde_json::from_str(&content).unwrap();
    
    // Modify ciphertext to invalid base64
    wallet["ciphertext"] = serde_json::Value::String("invalid!base64!".to_string());
    
    // Write back malformed wallet
    let malformed_content = serde_json::to_string_pretty(&wallet).unwrap();
    fs::write(&wallet_path, malformed_content).unwrap();
    
    // Should fail to load malformed ciphertext
    let result = WalletStorage::load_encrypted_wallet(wallet_name, &password);
    assert!(result.is_err(), "Malformed ciphertext should be rejected");
    
    // Clean up
    let _ = fs::remove_file(wallet_path);
}

#[test]
fn test_short_nonce_attack() {
    // Test that short/invalid nonces are rejected
    let wallet_name = "short_nonce_test";
    let password = Zeroizing::new("test_password".to_string());
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Save wallet normally
    WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &password).unwrap();
    
    let wallet_path = WalletStorage::get_wallet_path(wallet_name).unwrap();
    
    // Read and parse the wallet
    let content = fs::read_to_string(&wallet_path).unwrap();
    let mut wallet: serde_json::Value = serde_json::from_str(&content).unwrap();
    
    // Modify nonce to too short (should be 12 bytes for AES-GCM)
    wallet["nonce"] = serde_json::Value::String(general_purpose::STANDARD.encode([0u8; 8])); // Too short
    
    // Write back malformed wallet
    let malformed_content = serde_json::to_string_pretty(&wallet).unwrap();
    fs::write(&wallet_path, malformed_content).unwrap();
    
    // Should fail to load with invalid nonce
    let result = WalletStorage::load_encrypted_wallet(wallet_name, &password);
    assert!(result.is_err(), "Invalid nonce length should be rejected");
    
    // Clean up
    let _ = fs::remove_file(wallet_path);
}

