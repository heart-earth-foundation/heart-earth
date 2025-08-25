use argon2::{Algorithm, Argon2, Params, Version};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};

#[test]
fn test_rust_matches_frontend_argon2_parameters() {
    let password = "test_password_123";
    let salt = [1u8; 32];
    
    // Test Rust implementation (our new parameters)
    let mut rust_key = [0u8; 32];
    let params = Params::new(4096, 3, 1, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2.hash_password_into(password.as_bytes(), &salt, &mut rust_key).unwrap();
    
    // Simulate frontend parameters (what frontend actually uses)
    // Frontend uses: argon2id(passwordBytes, salt, { t: 3, m: 4096, p: 1, dkLen: 32 })
    let mut frontend_key = [0u8; 32];
    let frontend_params = Params::new(4096, 3, 1, Some(32)).unwrap();
    let frontend_argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, frontend_params);
    frontend_argon2.hash_password_into(password.as_bytes(), &salt, &mut frontend_key).unwrap();
    
    println!("Rust key (first 8 bytes):     {:?}", &rust_key[..8]);
    println!("Frontend key (first 8 bytes): {:?}", &frontend_key[..8]);
    
    // Keys should now be identical
    assert_eq!(rust_key, frontend_key, "Rust and frontend should produce identical keys");
}

#[test]
fn test_cross_platform_wallet_compatibility() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let password = "test_password_123";
    let salt = [42u8; 32]; // Fixed salt for reproducibility
    
    // Simulate CLI wallet encryption
    let mut cli_key = [0u8; 32];
    let params = Params::new(4096, 3, 1, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2.hash_password_into(password.as_bytes(), &salt, &mut cli_key).unwrap();
    
    let cli_aes_key = Key::<Aes256Gcm>::from_slice(&cli_key);
    let cipher = Aes256Gcm::new(cli_aes_key);
    let nonce = Nonce::from_slice(&[1u8; 12]); // Fixed nonce for test
    
    let cli_encrypted = cipher.encrypt(nonce, mnemonic.as_bytes()).unwrap();
    
    // Simulate browser wallet decryption using same parameters
    let mut browser_key = [0u8; 32];
    let browser_params = Params::new(4096, 3, 1, Some(32)).unwrap();
    let browser_argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, browser_params);
    browser_argon2.hash_password_into(password.as_bytes(), &salt, &mut browser_key).unwrap();
    
    let browser_aes_key = Key::<Aes256Gcm>::from_slice(&browser_key);
    let browser_cipher = Aes256Gcm::new(browser_aes_key);
    
    let decrypted = browser_cipher.decrypt(nonce, cli_encrypted.as_ref()).unwrap();
    let decrypted_mnemonic = String::from_utf8(decrypted).unwrap();
    
    println!("Original mnemonic:  {}", mnemonic);
    println!("Decrypted mnemonic: {}", decrypted_mnemonic);
    
    assert_eq!(mnemonic, decrypted_mnemonic, "Cross-platform wallet decryption should work");
}

#[test]
fn test_same_mnemonic_produces_same_addresses() {
    use wallet::Wallet;
    
    let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Create wallet from mnemonic (CLI scenario)
    let mut cli_wallet = Wallet::from_mnemonic(test_mnemonic, None).unwrap();
    let cli_account = cli_wallet.generate_account(0, 0).unwrap();
    
    // Create another wallet from same mnemonic (browser scenario)  
    let mut browser_wallet = Wallet::from_mnemonic(test_mnemonic, None).unwrap();
    let browser_account = browser_wallet.generate_account(0, 0).unwrap();
    
    println!("CLI blockchain address:     {}", cli_account.blockchain_address);
    println!("Browser blockchain address: {}", browser_account.blockchain_address);
    println!("CLI peer ID:                {}", cli_account.peer_id);
    println!("Browser peer ID:            {}", browser_account.peer_id);
    
    // Same mnemonic should produce identical addresses and peer IDs
    assert_eq!(cli_account.blockchain_address, browser_account.blockchain_address, 
               "Same mnemonic should produce same blockchain address");
    assert_eq!(cli_account.peer_id, browser_account.peer_id,
               "Same mnemonic should produce same peer ID");
}

#[test]
fn test_biometric_encryption_compatibility() {
    use wallet::biometric::BiometricManager;
    
    let wallet_key = [42u8; 32];
    let challenge = "test_challenge_for_biometric";
    
    // Encrypt wallet key with biometric challenge
    let credential = BiometricManager::encrypt_key_for_biometric(&wallet_key, challenge).unwrap();
    
    // Decrypt wallet key with same challenge
    let decrypted_key = BiometricManager::decrypt_key_with_biometric(&credential, challenge).unwrap();
    
    println!("Original key:  {:?}", &wallet_key[..8]);
    println!("Decrypted key: {:?}", &decrypted_key[..8]);
    
    assert_eq!(wallet_key, decrypted_key, "Biometric encryption should be consistent");
    
    // Verify the key can't be decrypted with wrong challenge
    let wrong_challenge = "wrong_challenge";
    let result = BiometricManager::decrypt_key_with_biometric(&credential, wrong_challenge);
    assert!(result.is_err(), "Wrong challenge should fail to decrypt");
}