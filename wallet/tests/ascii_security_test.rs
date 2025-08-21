// Test ASCII-only password enforcement for security
use wallet::{WalletStorage, Seed};
use zeroize::Zeroizing;
use std::fs;

#[test]
fn test_ascii_only_enforcement() {
    let wallet_name = "ascii_test";
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Test 1: ASCII password should work
    let ascii_password = Zeroizing::new("MySecurePassword123!".to_string());
    let result = WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &ascii_password);
    assert!(result.is_ok(), "ASCII password should be accepted");
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Test 2: Unicode password should be rejected
    let unicode_password = Zeroizing::new("café123".to_string());
    let result = WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &unicode_password);
    assert!(result.is_err(), "Unicode password should be rejected");
    
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("ASCII characters"), "Error should mention ASCII requirement");
    assert!(error_msg.contains("security reasons"), "Error should explain security rationale");
    
    // Test 3: Empty password should be rejected
    let empty_password = Zeroizing::new(String::new());
    let result = WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &empty_password);
    assert!(result.is_err(), "Empty password should be rejected");
    
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("cannot be empty"), "Error should mention empty password");
}

#[test]
fn test_unicode_rejection_on_load() {
    let wallet_name = "unicode_load_test";
    let ascii_password = Zeroizing::new("ValidPassword123".to_string());
    let unicode_password = Zeroizing::new("validpássword123".to_string());
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // Save with ASCII password
    WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &ascii_password).unwrap();
    
    // Try to load with Unicode password - should be rejected before attempting decryption
    let result = WalletStorage::load_encrypted_wallet(wallet_name, &unicode_password);
    assert!(result.is_err(), "Unicode password should be rejected on load");
    
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("ASCII characters"), "Error should mention ASCII requirement");
    
    // Verify ASCII password still works
    let loaded = WalletStorage::load_encrypted_wallet(wallet_name, &ascii_password).unwrap();
    assert_eq!(loaded, mnemonic);
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
}

#[test]
fn test_all_ascii_characters_allowed() {
    let wallet_name = "ascii_chars_test";
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Test various ASCII character sets
    let test_passwords = vec![
        "lowercase123",
        "UPPERCASE123", 
        "MixedCase123",
        "Numbers12345",
        "Symbols!@#$%^&*()",
        "Spaces Are OK 123",
        "Mix3d_Ch@rs-W1th.Numb3rs!",
    ];
    
    for (i, password_str) in test_passwords.iter().enumerate() {
        let test_wallet_name = format!("{}_{}", wallet_name, i);
        let password = Zeroizing::new(password_str.to_string());
        
        // Clean up
        if let Ok(path) = WalletStorage::get_wallet_path(&test_wallet_name) {
            let _ = fs::remove_file(path);
        }
        
        // Should accept all ASCII passwords
        let result = WalletStorage::save_encrypted_wallet(&test_wallet_name, &mnemonic, &password);
        assert!(result.is_ok(), "ASCII password '{}' should be accepted", password_str);
        
        // Should be able to load
        let loaded = WalletStorage::load_encrypted_wallet(&test_wallet_name, &password).unwrap();
        assert_eq!(loaded, mnemonic);
        
        // Clean up
        if let Ok(path) = WalletStorage::get_wallet_path(&test_wallet_name) {
            let _ = fs::remove_file(path);
        }
    }
}

#[test]
fn test_unicode_characters_rejected() {
    let wallet_name = "unicode_reject_test";
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Test various Unicode characters that should be rejected
    let unicode_passwords = vec![
        "café123",      // French accent
        "niño456",      // Spanish tilde  
        "naïve789",     // Diaeresis
        "résumé123",    // Multiple accents
        "中文密码",       // Chinese characters
        "пароль123",    // Cyrillic
        "🔑password",   // Emoji
        "Ħello123",     // Extended Latin
    ];
    
    for password_str in unicode_passwords {
        let password = Zeroizing::new(password_str.to_string());
        
        // Should reject all Unicode passwords
        let result = WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &password);
        assert!(result.is_err(), "Unicode password '{}' should be rejected", password_str);
        
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("ASCII characters"), 
            "Error for '{}' should mention ASCII requirement", password_str);
    }
}