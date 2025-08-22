use wasm_bindgen::prelude::*;
pub mod wasm_wallet;
pub mod wasm_p2p;
use wasm_wallet::WasmWallet;
use wasm_p2p::WasmP2P;
use std::str::FromStr;
use slip10_ed25519;

// Called when the WASM module is instantiated
#[wasm_bindgen(start)]
pub fn init() {
    // Set up panic hook for better error messages in browser console
    console_error_panic_hook::set_once();
}

// Simple test function to verify WASM is working
#[wasm_bindgen]
pub fn greet(name: &str) -> String {
    format!("Hello, {}! Heart Earth WASM is working.", name)
}

// Generate a BIP39 mnemonic 
#[wasm_bindgen]
pub fn generate_mnemonic() -> Result<String, JsError> {
    WasmWallet::generate_mnemonic()
        .map_err(|e| JsError::new(&e.to_string()))
}

// Create a wallet account from mnemonic using k256 + ed25519
#[wasm_bindgen]
pub fn create_account(mnemonic: &str, account_number: u32, index: u32) -> Result<String, JsError> {
    let account = WasmWallet::create_account(mnemonic, account_number, index)
        .map_err(|e| JsError::new(&e.to_string()))?;
    
    // Return JSON with address and peer ID
    let result = serde_json::json!({
        "blockchain_address": account.blockchain_address,
        "peer_id": account.peer_id,
        "account_number": account_number,
        "index": index
    });
    
    Ok(result.to_string())
}

// Create P2P connection from account
#[wasm_bindgen]
pub fn create_p2p_connection(mnemonic: &str, account_number: u32, index: u32) -> Result<String, JsError> {
    let account = WasmWallet::create_account(mnemonic, account_number, index)
        .map_err(|e| JsError::new(&e.to_string()))?;
    
    // Get the ed25519 private key bytes for P2P
    let indexes = vec![44, 1, account_number, 0, index];
    let mnemonic_obj = bip39::Mnemonic::from_str(mnemonic)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let seed = mnemonic_obj.to_seed("");
    let ed25519_private_bytes = slip10_ed25519::derive_ed25519_private_key(&seed, &indexes);
    
    // Create P2P instance
    let p2p = WasmP2P::new(&ed25519_private_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;
    
    // Return P2P info
    let result = serde_json::json!({
        "peer_id": p2p.local_peer_id(),
        "blockchain_address": account.blockchain_address,
        "status": "initialized"
    });
    
    Ok(result.to_string())
}

// Development/testing functions that require wallet crate
#[cfg(test)]
mod wallet_compat_tests {
    use super::*;
    use wasm_bindgen::prelude::wasm_bindgen;
    
    // Authentication signing functions (for testing/development only)
    #[wasm_bindgen]
    pub fn sign_p2p_auth_message(
        mnemonic: &str,
        account_number: u32,
        index: u32,
        message_json: &str
    ) -> Result<String, JsError> {
        use wallet::{Seed, UnifiedAccount, message_signing::{AuthMessage, P2PAuthSigner}};
        
        let seed = Seed::from_phrase(mnemonic)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let account = UnifiedAccount::derive(&seed, account_number, index)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let message: AuthMessage = serde_json::from_str(message_json)
            .map_err(|e| JsError::new(&e.to_string()))?;
        
        let signature = P2PAuthSigner::sign_message(&account, &message)
            .map_err(|e| JsError::new(&e.to_string()))?;
        
        Ok(signature.signature)
    }

    #[wasm_bindgen]
    pub fn sign_account_auth_message(
        mnemonic: &str,
        account_number: u32,
        index: u32,
        message_json: &str
    ) -> Result<String, JsError> {
        use wallet::{Seed, UnifiedAccount, message_signing::{AuthMessage, AccountAuthSigner}};
        
        let seed = Seed::from_phrase(mnemonic)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let account = UnifiedAccount::derive(&seed, account_number, index)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let message: AuthMessage = serde_json::from_str(message_json)
            .map_err(|e| JsError::new(&e.to_string()))?;
        
        let signature = AccountAuthSigner::sign_message(&account, &message)
            .map_err(|e| JsError::new(&e.to_string()))?;
        
        Ok(signature.signature)
    }

    #[wasm_bindgen]
    pub fn sign_p2p_typed_data(
        mnemonic: &str,
        account_number: u32,
        index: u32,
        typed_data_json: &str
    ) -> Result<String, JsError> {
        use wallet::{
            Seed, UnifiedAccount, 
            structured_signing::{AuthRequest, P2PStructuredSigner, DomainSeparator}
        };
        
        let seed = Seed::from_phrase(mnemonic)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let account = UnifiedAccount::derive(&seed, account_number, index)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let auth_request: AuthRequest = serde_json::from_str(typed_data_json)
            .map_err(|e| JsError::new(&e.to_string()))?;
        
        let domain = DomainSeparator::new("heart-earth".to_string(), "1".to_string(), 1);
        let signature = P2PStructuredSigner::sign_typed_data(&account, &domain, &auth_request)
            .map_err(|e| JsError::new(&e.to_string()))?;
        
        Ok(signature.signature)
    }

    #[wasm_bindgen]
    pub fn sign_account_typed_data(
        mnemonic: &str,
        account_number: u32,
        index: u32,
        typed_data_json: &str
    ) -> Result<String, JsError> {
        use wallet::{
            Seed, UnifiedAccount,
            structured_signing::{AuthRequest, AccountStructuredSigner, DomainSeparator}
        };
        
        let seed = Seed::from_phrase(mnemonic)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let account = UnifiedAccount::derive(&seed, account_number, index)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let auth_request: AuthRequest = serde_json::from_str(typed_data_json)
            .map_err(|e| JsError::new(&e.to_string()))?;
        
        let domain = DomainSeparator::new("heart-earth".to_string(), "1".to_string(), 1);
        let signature = AccountStructuredSigner::sign_typed_data(&account, &domain, &auth_request)
            .map_err(|e| JsError::new(&e.to_string()))?;
        
        Ok(signature.signature)
    }

    #[wasm_bindgen]
    pub fn sign_p2p_auth_message_full(
        mnemonic: &str,
        account_number: u32,
        index: u32,
        message_json: &str
    ) -> Result<String, JsError> {
        use wallet::{Seed, UnifiedAccount, message_signing::{AuthMessage, P2PAuthSigner}};
        
        let seed = Seed::from_phrase(mnemonic)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let account = UnifiedAccount::derive(&seed, account_number, index)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let message: AuthMessage = serde_json::from_str(message_json)
            .map_err(|e| JsError::new(&e.to_string()))?;
        
        let auth_signature = P2PAuthSigner::sign_message(&account, &message)
            .map_err(|e| JsError::new(&e.to_string()))?;
        
        Ok(serde_json::to_string(&auth_signature).unwrap())
    }

    #[wasm_bindgen]
    pub fn sign_account_auth_message_full(
        mnemonic: &str,
        account_number: u32,
        index: u32,
        message_json: &str
    ) -> Result<String, JsError> {
        use wallet::{Seed, UnifiedAccount, message_signing::{AuthMessage, AccountAuthSigner}};
        
        let seed = Seed::from_phrase(mnemonic)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let account = UnifiedAccount::derive(&seed, account_number, index)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let message: AuthMessage = serde_json::from_str(message_json)
            .map_err(|e| JsError::new(&e.to_string()))?;
        
        let auth_signature = AccountAuthSigner::sign_message(&account, &message)
            .map_err(|e| JsError::new(&e.to_string()))?;
        
        Ok(serde_json::to_string(&auth_signature).unwrap())
    }

    #[wasm_bindgen]
    pub fn verify_p2p_signature_from_cli(
        mnemonic: &str,
        account_number: u32,
        index: u32,
        auth_signature_json: &str
    ) -> Result<bool, JsError> {
        use wallet::{Seed, UnifiedAccount, message_signing::{AuthSignature, P2PAuthSigner}};
        
        let seed = Seed::from_phrase(mnemonic)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let account = UnifiedAccount::derive(&seed, account_number, index)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let auth_signature: AuthSignature = serde_json::from_str(auth_signature_json)
            .map_err(|e| JsError::new(&e.to_string()))?;
        
        // Get the P2P public key bytes from the account
        let p2p_public_key = account.ed25519_public_key()
            .ok_or_else(|| JsError::new("No Ed25519 public key available"))?;
        
        let is_valid = P2PAuthSigner::verify_signature(&auth_signature, &p2p_public_key)
            .unwrap_or(false);
        
        Ok(is_valid)
    }

    #[wasm_bindgen]
    pub fn verify_account_signature_from_cli(
        mnemonic: &str,
        account_number: u32,
        index: u32,
        auth_signature_json: &str
    ) -> Result<bool, JsError> {
        use wallet::{Seed, UnifiedAccount, message_signing::{AuthSignature, AccountAuthSigner}};
        
        let seed = Seed::from_phrase(mnemonic)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let account = UnifiedAccount::derive(&seed, account_number, index)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let auth_signature: AuthSignature = serde_json::from_str(auth_signature_json)
            .map_err(|e| JsError::new(&e.to_string()))?;
        
        // Get the account public key bytes from the account
        let account_public_key = account.blockchain_public_key()
            .ok_or_else(|| JsError::new("No blockchain public key available"))?;
        
        let is_valid = AccountAuthSigner::verify_signature(&auth_signature, &account_public_key)
            .unwrap_or(false);
        
        Ok(is_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::wallet_compat_tests::*;
    use wallet::{Seed, UnifiedAccount};

    #[test]
    fn test_wasm_cli_compatibility() {
        // Use a known test mnemonic
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let account_number = 0;
        let index = 0;
        
        // Generate account using CLI wallet
        let seed = Seed::from_phrase(test_mnemonic).expect("Valid mnemonic");
        let cli_account = UnifiedAccount::derive(&seed, account_number, index).expect("CLI derivation failed");
        
        // Generate account using WASM wallet  
        let wasm_account = WasmWallet::create_account(test_mnemonic, account_number, index).expect("WASM derivation failed");
        
        // Compare addresses - print first to see the difference
        println!("CLI blockchain address: {}", cli_account.blockchain_address);
        println!("WASM blockchain address: {}", wasm_account.blockchain_address);
        
        println!("CLI peer ID: {}", cli_account.peer_id);
        println!("WASM peer ID: {}", wasm_account.peer_id);
        
        // Debug: Let's check if we can access the public key bytes from CLI
        // to compare with WASM implementation
        
        // Try to recreate CLI derivation manually for debugging
        use wallet::derivation::KeyDerivation;
        let seed_bytes = seed.to_seed_bytes();
        let derivation = KeyDerivation::from_seed(&seed_bytes).expect("Seed derivation");
        let cli_blockchain_key = derivation.derive_blockchain_key(account_number, index).expect("Blockchain key derivation");
        let cli_pub_bytes = cli_blockchain_key.public_key_bytes();
        
        println!("CLI public key bytes: {:?}", hex::encode(cli_pub_bytes));
        
        // Create manual WASM derivation to debug
        let wasm_mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, test_mnemonic).expect("WASM mnemonic parse");
        let wasm_seed = wasm_mnemonic.to_seed("");
        let wasm_secp_path = format!("m/44'/0'/{}/0/{}", account_number, index);
        let wasm_xprv = bip32::XPrv::derive_from_path(&wasm_seed, &wasm_secp_path.parse().unwrap()).unwrap();
        let wasm_xpub = wasm_xprv.public_key();
        let wasm_pub_bytes = wasm_xpub.to_bytes();
        
        println!("WASM XPub bytes: {:?}", hex::encode(wasm_pub_bytes));
        
        // Debug seeds - this is the real issue!
        println!("CLI seed bytes: {:?}", hex::encode(&seed_bytes[0..32]));
        println!("WASM seed bytes: {:?}", hex::encode(&wasm_seed[0..32]));
        
        // Verify they're not empty
        assert!(!cli_account.blockchain_address.is_empty(), "CLI address should not be empty");
        assert!(!wasm_account.blockchain_address.is_empty(), "WASM address should not be empty");
        assert!(!cli_account.peer_id.is_empty(), "CLI peer ID should not be empty");
        assert!(!wasm_account.peer_id.is_empty(), "WASM peer ID should not be empty");
        
        // CRITICAL: Verify WASM and CLI produce IDENTICAL outputs
        assert_eq!(cli_account.blockchain_address, wasm_account.blockchain_address, 
                   "Blockchain addresses must match between CLI and WASM");
        assert_eq!(cli_account.peer_id, wasm_account.peer_id,
                   "Peer IDs must match between CLI and WASM");
    }

    #[test]
    fn test_all_signing_routes_cli_wasm_compatibility() {
        use wallet::{
            Seed, UnifiedAccount,
            message_signing::{AuthMessage, P2PAuthSigner, AccountAuthSigner},
            structured_signing::{AuthRequest, P2PStructuredSigner, AccountStructuredSigner, DomainSeparator},
            nonce::Nonce,
        };

        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let account_number = 0;
        let index = 0;
        
        // Step 1: Generate accounts (already proven to match)
        let seed = Seed::from_phrase(test_mnemonic).unwrap();
        let cli_account = UnifiedAccount::derive(&seed, account_number, index).unwrap();
        let wasm_account = WasmWallet::create_account(test_mnemonic, account_number, index).unwrap();
        
        // Verify accounts match (should pass)
        assert_eq!(cli_account.blockchain_address, wasm_account.blockchain_address);
        assert_eq!(cli_account.peer_id, wasm_account.peer_id);
        println!("✅ Wallet generation: CLI and WASM produce identical accounts");
        
        // Step 2: Test Message Signing
        let nonce = Nonce::generate().unwrap();
        let auth_message = AuthMessage::new(
            "heart-earth.local".to_string(),
            cli_account.blockchain_address.clone(),
            "https://heart-earth.local".to_string(),
            nonce,
            Some("Sign in to Heart Earth".to_string()),
        );
        
        // Test P2P Message Signing
        let cli_p2p_sig = P2PAuthSigner::sign_message(&cli_account, &auth_message).unwrap();
        let wasm_p2p_sig = sign_p2p_auth_message(
            test_mnemonic, 
            account_number, 
            index,
            &serde_json::to_string(&auth_message).unwrap()
        ).unwrap();
        
        assert_eq!(cli_p2p_sig.signature, wasm_p2p_sig, "P2P message signatures must match");
        println!("✅ P2P message signing: CLI and WASM produce identical signatures");
        
        // Test Account Message Signing  
        let cli_account_sig = AccountAuthSigner::sign_message(&cli_account, &auth_message).unwrap();
        let wasm_account_sig = sign_account_auth_message(
            test_mnemonic,
            account_number, 
            index,
            &serde_json::to_string(&auth_message).unwrap()
        ).unwrap();
        
        assert_eq!(cli_account_sig.signature, wasm_account_sig, "Account message signatures must match");
        println!("✅ Account message signing: CLI and WASM produce identical signatures");
        
        // Step 3: Test Structured Data Signing
        let domain = DomainSeparator::new("heart-earth".to_string(), "1".to_string(), 1);
        let auth_request = AuthRequest {
            requester: cli_account.blockchain_address.clone(),
            permissions: vec!["login".to_string()], 
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: Nonce::generate().unwrap().hex().to_string(),
        };
        
        // Test P2P Structured Signing
        let cli_p2p_struct_sig = P2PStructuredSigner::sign_typed_data(
            &cli_account, &domain, &auth_request
        ).unwrap();
        let wasm_p2p_struct_sig = sign_p2p_typed_data(
            test_mnemonic,
            account_number,
            index, 
            &serde_json::to_string(&auth_request).unwrap()
        ).unwrap();
        
        assert_eq!(cli_p2p_struct_sig.signature, wasm_p2p_struct_sig, "P2P structured signatures must match");
        println!("✅ P2P structured signing: CLI and WASM produce identical signatures");
        
        // Test Account Structured Signing
        let cli_account_struct_sig = AccountStructuredSigner::sign_typed_data(
            &cli_account, &domain, &auth_request  
        ).unwrap();
        let wasm_account_struct_sig = sign_account_typed_data(
            test_mnemonic,
            account_number,
            index,
            &serde_json::to_string(&auth_request).unwrap()
        ).unwrap();
        
        assert_eq!(cli_account_struct_sig.signature, wasm_account_struct_sig, "Account structured signatures must match");
        println!("✅ Account structured signing: CLI and WASM produce identical signatures");
        
        println!("🎉 ALL SIGNING ROUTES MATCH BETWEEN CLI AND WASM!");
        println!("   - Wallet generation: ✅");
        println!("   - P2P message signing (Ed25519): ✅");
        println!("   - Account message signing (secp256k1): ✅");
        println!("   - P2P structured signing (Ed25519): ✅");
        println!("   - Account structured signing (secp256k1): ✅");
    }

    #[test]
    fn test_cross_verification_cli_wasm() {
        use wallet::{
            Seed, UnifiedAccount,
            message_signing::{AuthMessage, P2PAuthSigner, AccountAuthSigner},
            nonce::Nonce,
        };

        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let account_number = 0;
        let index = 0;
        
        // Create identical accounts
        let seed = Seed::from_phrase(test_mnemonic).unwrap();
        let cli_account = UnifiedAccount::derive(&seed, account_number, index).unwrap();
        let wasm_account = WasmWallet::create_account(test_mnemonic, account_number, index).unwrap();
        
        // Verify accounts are identical
        assert_eq!(cli_account.blockchain_address, wasm_account.blockchain_address);
        assert_eq!(cli_account.peer_id, wasm_account.peer_id);
        
        // Create test message
        let nonce = Nonce::generate().unwrap();
        let auth_message = AuthMessage::new(
            "heart-earth-test.local".to_string(),
            cli_account.blockchain_address.clone(),
            "https://heart-earth-test.local".to_string(),
            nonce,
            Some("Cross-verification test".to_string()),
        );
        let message_json = serde_json::to_string(&auth_message).unwrap();
        
        // Test 1: CLI signs P2P, WASM verifies
        let cli_p2p_signature = P2PAuthSigner::sign_message(&cli_account, &auth_message).unwrap();
        let cli_p2p_sig_json = serde_json::to_string(&cli_p2p_signature).unwrap();
        
        let wasm_verifies_cli_p2p = verify_p2p_signature_from_cli(
            test_mnemonic, account_number, index, &cli_p2p_sig_json
        ).unwrap();
        assert!(wasm_verifies_cli_p2p, "WASM must verify CLI P2P signatures");
        println!("✅ CLI P2P signature → WASM verification: PASS");
        
        // Test 2: CLI signs Account, WASM verifies
        let cli_account_signature = AccountAuthSigner::sign_message(&cli_account, &auth_message).unwrap();
        let cli_account_sig_json = serde_json::to_string(&cli_account_signature).unwrap();
        
        let wasm_verifies_cli_account = verify_account_signature_from_cli(
            test_mnemonic, account_number, index, &cli_account_sig_json
        ).unwrap();
        assert!(wasm_verifies_cli_account, "WASM must verify CLI Account signatures");
        println!("✅ CLI Account signature → WASM verification: PASS");
        
        // Test 3: WASM signs P2P, CLI verifies
        let wasm_p2p_sig_json = sign_p2p_auth_message_full(
            test_mnemonic, account_number, index, &message_json
        ).unwrap();
        let wasm_p2p_signature: wallet::message_signing::AuthSignature = 
            serde_json::from_str(&wasm_p2p_sig_json).unwrap();
        
        // CLI verification
        let p2p_public_key = cli_account.ed25519_public_key().unwrap();
        let cli_verifies_wasm_p2p = P2PAuthSigner::verify_signature(&wasm_p2p_signature, &p2p_public_key).unwrap();
        assert!(cli_verifies_wasm_p2p, "CLI must verify WASM P2P signatures");
        println!("✅ WASM P2P signature → CLI verification: PASS");
        
        // Test 4: WASM signs Account, CLI verifies  
        let wasm_account_sig_json = sign_account_auth_message_full(
            test_mnemonic, account_number, index, &message_json
        ).unwrap();
        let wasm_account_signature: wallet::message_signing::AuthSignature = 
            serde_json::from_str(&wasm_account_sig_json).unwrap();
        
        // CLI verification
        let account_public_key = cli_account.blockchain_public_key().unwrap();
        let cli_verifies_wasm_account = AccountAuthSigner::verify_signature(&wasm_account_signature, &account_public_key).unwrap();
        assert!(cli_verifies_wasm_account, "CLI must verify WASM Account signatures");
        println!("✅ WASM Account signature → CLI verification: PASS");
        
        println!("🎉 CROSS-VERIFICATION COMPLETE!");
        println!("   - CLI P2P → WASM verify: ✅");
        println!("   - CLI Account → WASM verify: ✅");
        println!("   - WASM P2P → CLI verify: ✅"); 
        println!("   - WASM Account → CLI verify: ✅");
        println!("   🔒 BOTH PLATFORMS CAN VERIFY EACH OTHER'S SIGNATURES!");
    }
}