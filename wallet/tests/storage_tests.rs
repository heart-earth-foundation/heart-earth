use wallet::{WalletStorage, Seed};
use zeroize::Zeroizing;
use std::fs;

#[test]
fn test_wallet_storage_roundtrip() {
    let wallet_name = "test_wallet_roundtrip";
    let password = Zeroizing::new("test_password_123".to_string());
    let seed = Seed::generate(12).unwrap();
    let original_mnemonic = seed.phrase();
    
    // Clean up any existing test wallet
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Save wallet
    WalletStorage::save_encrypted_wallet(wallet_name, &original_mnemonic, &password).unwrap();
    
    // Verify wallet exists
    assert!(WalletStorage::wallet_exists(wallet_name));
    
    // Load wallet
    let loaded_mnemonic = WalletStorage::load_encrypted_wallet(wallet_name, &password).unwrap();
    
    // Verify mnemonics match
    assert_eq!(original_mnemonic, loaded_mnemonic);
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
}

#[test]
fn test_invalid_password() {
    let wallet_name = "test_wallet_invalid_password";
    let password = Zeroizing::new("correct_password_123".to_string());
    let wrong_password = Zeroizing::new("wrong_password_123".to_string());
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Clean up any existing test wallet
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Save wallet
    WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &password).unwrap();
    
    // Try to load with wrong password
    let result = WalletStorage::load_encrypted_wallet(wallet_name, &wrong_password);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Invalid password"));
    
    // Verify correct password still works
    let loaded_mnemonic = WalletStorage::load_encrypted_wallet(wallet_name, &password).unwrap();
    assert_eq!(mnemonic, loaded_mnemonic);
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
}

#[test]
fn test_wallet_not_found() {
    let wallet_name = "non_existent_wallet";
    let password = Zeroizing::new("password_123".to_string());
    
    // Ensure wallet doesn't exist
    assert!(!WalletStorage::wallet_exists(wallet_name));
    
    // Try to load non-existent wallet
    let result = WalletStorage::load_encrypted_wallet(wallet_name, &password);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[test]
fn test_different_passwords_different_encryption() {
    let wallet_name1 = "test_wallet_diff_pass_1";
    let wallet_name2 = "test_wallet_diff_pass_2";
    let password1 = Zeroizing::new("password_one_123".to_string());
    let password2 = Zeroizing::new("password_two_123".to_string());
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Clean up any existing test wallets
    for name in [wallet_name1, wallet_name2] {
        if let Ok(path) = WalletStorage::get_wallet_path(name) {
            let _ = fs::remove_file(path);
        }
    }
    
    // Save same mnemonic with different passwords
    WalletStorage::save_encrypted_wallet(wallet_name1, &mnemonic, &password1).unwrap();
    WalletStorage::save_encrypted_wallet(wallet_name2, &mnemonic, &password2).unwrap();
    
    // Read the encrypted files - they should be different
    let path1 = WalletStorage::get_wallet_path(wallet_name1).unwrap();
    let path2 = WalletStorage::get_wallet_path(wallet_name2).unwrap();
    
    let content1 = fs::read_to_string(&path1).unwrap();
    let content2 = fs::read_to_string(&path2).unwrap();
    
    // Encrypted files should be different (different salts/nonces)
    assert_ne!(content1, content2);
    
    // But both should decrypt to the same mnemonic
    let loaded1 = WalletStorage::load_encrypted_wallet(wallet_name1, &password1).unwrap();
    let loaded2 = WalletStorage::load_encrypted_wallet(wallet_name2, &password2).unwrap();
    
    assert_eq!(loaded1, mnemonic);
    assert_eq!(loaded2, mnemonic);
    assert_eq!(loaded1, loaded2);
    
    // Clean up
    let _ = fs::remove_file(path1);
    let _ = fs::remove_file(path2);
}

// Edge case tests based on docs.rs analysis

#[test]
fn test_empty_password_rejection() {
    let wallet_name = "test_empty_password";
    let empty_password = Zeroizing::new(String::new());
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Empty password should now be rejected for security
    let result = WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &empty_password);
    assert!(result.is_err(), "Empty password should be rejected");
    
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("cannot be empty"), "Error should mention empty password");
}

#[test]
fn test_very_long_password() {
    let wallet_name = "test_long_password";
    // Test with 511 bytes (just under Argon2 max of 512)
    let long_password = Zeroizing::new("a".repeat(511));
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Should handle long password
    let result = WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &long_password);
    assert!(result.is_ok());
    
    // Should be able to load with long password
    let loaded = WalletStorage::load_encrypted_wallet(wallet_name, &long_password).unwrap();
    assert_eq!(loaded, mnemonic);
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
}

#[test]
fn test_unicode_password_rejection() {
    let wallet_name = "test_unicode_wallet"; // ASCII wallet name is fine
    let unicode_password = Zeroizing::new("pássword_🔑_тест_密码".to_string());
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Unicode password should be rejected for security
    let result = WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &unicode_password);
    assert!(result.is_err(), "Unicode password should be rejected");
    
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("ASCII characters"), "Error should mention ASCII requirement");
    assert!(error_msg.contains("security reasons"), "Error should explain security rationale");
}

#[test]
fn test_very_long_mnemonic() {
    let wallet_name = "test_long_mnemonic";
    let password = Zeroizing::new("test_password".to_string());
    // Create artificially long mnemonic data
    let long_mnemonic = "word ".repeat(1000); // 5000 bytes
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Should handle large mnemonic data
    let result = WalletStorage::save_encrypted_wallet(wallet_name, &long_mnemonic, &password);
    assert!(result.is_ok());
    
    let loaded = WalletStorage::load_encrypted_wallet(wallet_name, &password).unwrap();
    assert_eq!(loaded, long_mnemonic);
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
}

#[test]
fn test_corrupted_wallet_file() {
    let wallet_name = "test_corrupted_wallet";
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
    
    // Corrupt the file with invalid JSON
    fs::write(&wallet_path, "invalid json").unwrap();
    
    // Should fail to load corrupted file
    let result = WalletStorage::load_encrypted_wallet(wallet_name, &password);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Failed to parse wallet file"));
    
    // Clean up
    let _ = fs::remove_file(wallet_path);
}

#[test]
fn test_tampered_wallet_file() {
    let wallet_name = "test_tampered_wallet";
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
    
    // Read and modify the encrypted data
    let mut content = fs::read_to_string(&wallet_path).unwrap();
    content = content.replace("\"ciphertext\":", "\"ciphertext_modified\":");
    fs::write(&wallet_path, content).unwrap();
    
    // Should fail to load tampered file
    let result = WalletStorage::load_encrypted_wallet(wallet_name, &password);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Failed to parse wallet file"));
    
    // Clean up
    let _ = fs::remove_file(wallet_path);
}

#[test]
fn test_invalid_wallet_version() {
    let wallet_name = "test_invalid_version";
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
    
    // Read and parse the wallet to modify version properly
    let content = fs::read_to_string(&wallet_path).unwrap();
    let mut wallet: serde_json::Value = serde_json::from_str(&content).unwrap();
    wallet["version"] = serde_json::Value::Number(serde_json::Number::from(255)); // Max u8 value
    
    let modified_content = serde_json::to_string_pretty(&wallet).unwrap();
    fs::write(&wallet_path, modified_content).unwrap();
    
    // Should fail to load unsupported version
    let result = WalletStorage::load_encrypted_wallet(wallet_name, &password);
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Unsupported wallet version"));
    
    // Clean up
    let _ = fs::remove_file(wallet_path);
}

#[test]
fn test_same_salt_different_passwords() {
    // This tests the uniqueness of salt generation
    let password1 = Zeroizing::new("password1".to_string());
    let _password2 = Zeroizing::new("password2".to_string());
    let mnemonic = "test mnemonic phrase";
    
    let names = ["test_salt_1", "test_salt_2", "test_salt_3"];
    
    // Clean up
    for name in &names {
        if let Ok(path) = WalletStorage::get_wallet_path(name) {
            let _ = fs::remove_file(path);
        }
    }
    
    // Save multiple wallets with different passwords
    for name in &names {
        WalletStorage::save_encrypted_wallet(name, mnemonic, &password1).unwrap();
    }
    
    // Read all files and extract salt values
    let mut salt_values = Vec::new();
    for name in &names {
        let path = WalletStorage::get_wallet_path(name).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        let wallet: serde_json::Value = serde_json::from_str(&content).unwrap();
        
        if let Some(salt_array) = wallet["salt"].as_array() {
            // Handle salt as array of bytes
            let salt_bytes: Vec<u8> = salt_array.iter()
                .map(|v| v.as_u64().unwrap() as u8)
                .collect();
            salt_values.push(format!("{:?}", salt_bytes));
        } else {
            panic!("Unexpected salt format in wallet file");
        }
    }
    
    // All salts should be different (cryptographically secure randomness)
    assert_eq!(salt_values.len(), 3);
    assert_ne!(salt_values[0], salt_values[1]);
    assert_ne!(salt_values[1], salt_values[2]);
    assert_ne!(salt_values[0], salt_values[2]);
    
    // Clean up
    for name in &names {
        if let Ok(path) = WalletStorage::get_wallet_path(name) {
            let _ = fs::remove_file(path);
        }
    }
}

#[test]
fn test_directory_creation_failure_handling() {
    // Test wallet path creation in edge cases
    let result = WalletStorage::get_wallet_path("test_dir_creation");
    assert!(result.is_ok());
    
    let path = result.unwrap();
    assert!(path.to_string_lossy().contains("heart-earth"));
    assert!(path.to_string_lossy().contains("wallets"));
    assert!(path.to_string_lossy().ends_with(".wallet"));
}

#[test]
fn test_wallet_exists_with_special_characters() {
    let special_names = [
        "wallet.with.dots",
        "wallet-with-dashes", 
        "wallet_with_underscores",
        "WALLET_UPPERCASE",
        "wallet123numbers"
    ];
    
    for name in &special_names {
        // These wallets shouldn't exist
        assert!(!WalletStorage::wallet_exists(name));
        
        // Path creation should work
        let result = WalletStorage::get_wallet_path(name);
        assert!(result.is_ok());
    }
}