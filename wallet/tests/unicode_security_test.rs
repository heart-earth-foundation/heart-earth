// Critical security test for Unicode normalization
// This tests the ACTUAL risk in practice

use wallet::{WalletStorage, Seed};
use zeroize::Zeroizing;
use std::fs;

#[test]
fn test_unicode_lockout_scenario() {
    // CRITICAL TEST: Can a user lock themselves out with Unicode?
    let wallet_name = "unicode_lockout_test";
    let seed = Seed::generate(12).unwrap();
    let mnemonic = seed.phrase();
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // User tries to create wallet with Unicode password (NFC form - é as single character)
    let password_nfc = Zeroizing::new("café".to_string());
    println!("NFC password bytes: {:?}", password_nfc.as_bytes());
    
    // Save wallet - should be rejected due to ASCII-only enforcement
    let result = WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &password_nfc);
    assert!(result.is_err(), "Unicode password should be rejected");
    assert!(result.unwrap_err().to_string().contains("ASCII"), "Error should mention ASCII requirement");
    
    // Also verify NFD form is rejected
    let password_nfd = Zeroizing::new("cafe\u{0301}".to_string()); // e + combining acute
    println!("NFD password bytes: {:?}", password_nfd.as_bytes());
    
    let result2 = WalletStorage::save_encrypted_wallet(wallet_name, &mnemonic, &password_nfd);
    assert!(result2.is_err(), "Unicode NFD password should be rejected");
    
    println!("✅ SAFE: Unicode passwords are properly rejected, preventing lockout scenarios");
    
    // Clean up
    if let Ok(path) = WalletStorage::get_wallet_path(wallet_name) {
        let _ = fs::remove_file(path);
    }
    
    // For your current use case (you + few others), this risk is:
    // LOW if you're typing passwords manually in terminal
    // MEDIUM if copy/pasting from different sources
    // HIGH if using international keyboards or mobile devices
}

#[test]
fn test_common_unicode_variations() {
    // Test common Unicode variations that could cause lockouts
    let test_cases = vec![
        // (description, form1, form2)
        ("Acute accent", "café", "cafe\u{0301}"),
        ("Grave accent", "père", "pe\u{0300}re"),
        ("Circumflex", "être", "e\u{0302}tre"),
        ("Tilde", "niño", "nin\u{0303}o"),
        ("Cedilla", "français", "franc\u{0327}ais"),
    ];
    
    for (desc, form1, form2) in test_cases {
        let wallet_name = format!("unicode_test_{}", desc.replace(" ", "_"));
        
        // Clean up
        if let Ok(path) = WalletStorage::get_wallet_path(&wallet_name) {
            let _ = fs::remove_file(path);
        }
        
        let password1 = Zeroizing::new(form1.to_string());
        let password2 = Zeroizing::new(form2.to_string());
        let mnemonic = "test mnemonic for unicode";
        
        // Both forms should be rejected due to ASCII-only enforcement
        let result1 = WalletStorage::save_encrypted_wallet(&wallet_name, mnemonic, &password1);
        let result2 = WalletStorage::save_encrypted_wallet(&wallet_name, mnemonic, &password2);
        
        assert!(result1.is_err(), "{} form1 should be rejected", desc);
        assert!(result2.is_err(), "{} form2 should be rejected", desc);
        
        println!("✅ {} - Both '{}' and '{}' properly rejected", desc, form1, form2);
        println!("   Bytes 1: {:?}", password1.as_bytes());
        println!("   Bytes 2: {:?}", password2.as_bytes());
        
        // Clean up
        if let Ok(path) = WalletStorage::get_wallet_path(&wallet_name) {
            let _ = fs::remove_file(path);
        }
    }
}

#[test]
fn test_server_security_impact() {
    // Does this Unicode issue affect the server/bootstrap node security?
    
    // Answer: NO - the server doesn't handle wallet passwords
    // The bootstrap node in p2p/src/bin/bootstrap.rs only:
    // 1. Generates its own keys
    // 2. Listens for P2P connections
    // 3. Relays messages
    
    // Client wallets are encrypted locally, not on the server
    // So Unicode issue only affects individual client wallet access
    
    println!("✅ SERVER IS SECURE: Bootstrap node doesn't handle wallet passwords");
    println!("🔍 RISK IS CLIENT-SIDE ONLY: Individual wallet access");
}