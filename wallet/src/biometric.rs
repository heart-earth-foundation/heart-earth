#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
#[cfg(feature = "wasm")]
use web_sys::{CredentialsContainer, PublicKeyCredential, Navigator, window};
#[cfg(feature = "wasm")]
use js_sys::{Promise, Uint8Array, Object};

use serde::{Serialize, Deserialize};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use rand::rngs::OsRng;
use rand::RngCore;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use crate::error::WalletError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricCredential {
    pub credential_id: String,
    pub user_handle: String,
    pub encrypted_key: String,
    pub nonce: String,
    pub salt: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricChallenge {
    pub challenge: String,
    pub timeout: u32,
    pub user_verification: String,
}

impl BiometricChallenge {
    pub fn new() -> Result<Self, WalletError> {
        let mut challenge_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut challenge_bytes);
        
        Ok(Self {
            challenge: URL_SAFE_NO_PAD.encode(&challenge_bytes),
            timeout: 60000, // 60 seconds
            user_verification: "required".to_string(),
        })
    }
}

pub struct BiometricManager;

impl BiometricManager {
    /// Check if biometric authentication is available in the current environment
    #[cfg(feature = "wasm")]
    pub fn is_available() -> bool {
        if let Some(window) = window() {
            if let Some(navigator) = window.navigator() {
                return navigator.credentials().is_some();
            }
        }
        false
    }
    
    #[cfg(not(feature = "wasm"))]
    pub fn is_available() -> bool {
        false
    }
    
    /// Encrypt a wallet key with a challenge that can be unlocked with biometric auth
    pub fn encrypt_key_for_biometric(
        wallet_key: &[u8; 32],
        challenge: &str,
    ) -> Result<BiometricCredential, WalletError> {
        // Use challenge as password for key derivation
        let challenge_bytes = challenge.as_bytes();
        
        // Generate salt for Argon2
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        
        // Derive AES key from challenge
        let mut derived_key = [0u8; 32];
        let params = argon2::Params::new(4096, 3, 1, Some(32))
            .map_err(|e| WalletError::Storage(format!("Invalid Argon2 params: {}", e)))?;
        let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        argon2.hash_password_into(challenge_bytes, &salt, &mut derived_key)
            .map_err(|e| WalletError::Storage(format!("Key derivation failed: {}", e)))?;
        
        // Encrypt wallet key
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let encrypted_key = cipher.encrypt(nonce, wallet_key.as_ref())
            .map_err(|e| WalletError::Storage(format!("Encryption failed: {}", e)))?;
        
        // Generate credential ID and user handle
        let mut credential_id = [0u8; 32];
        let mut user_handle = [0u8; 16];
        OsRng.fill_bytes(&mut credential_id);
        OsRng.fill_bytes(&mut user_handle);
        
        Ok(BiometricCredential {
            credential_id: URL_SAFE_NO_PAD.encode(&credential_id),
            user_handle: URL_SAFE_NO_PAD.encode(&user_handle),
            encrypted_key: URL_SAFE_NO_PAD.encode(&encrypted_key),
            nonce: URL_SAFE_NO_PAD.encode(&nonce_bytes),
            salt: URL_SAFE_NO_PAD.encode(&salt), // Store salt for decryption
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
    
    /// Decrypt a wallet key using a verified biometric challenge
    pub fn decrypt_key_with_biometric(
        credential: &BiometricCredential,
        challenge: &str,
    ) -> Result<[u8; 32], WalletError> {
        let challenge_bytes = challenge.as_bytes();
        
        // Derive the same AES key from challenge using stored salt
        let mut derived_key = [0u8; 32];
        
        let salt_bytes = URL_SAFE_NO_PAD.decode(&credential.salt)
            .map_err(|e| WalletError::Storage(format!("Invalid salt: {}", e)))?;
        let mut salt = [0u8; 32];
        if salt_bytes.len() == 32 {
            salt.copy_from_slice(&salt_bytes);
        } else {
            return Err(WalletError::Storage("Invalid salt length".to_string()));
        }
        
        let params = argon2::Params::new(4096, 3, 1, Some(32))
            .map_err(|e| WalletError::Storage(format!("Invalid Argon2 params: {}", e)))?;
        let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        argon2.hash_password_into(challenge_bytes, &salt, &mut derived_key)
            .map_err(|e| WalletError::Storage(format!("Key derivation failed: {}", e)))?;
        
        // Decrypt wallet key
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
        let nonce_bytes = URL_SAFE_NO_PAD.decode(&credential.nonce)
            .map_err(|e| WalletError::Storage(format!("Invalid nonce: {}", e)))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let encrypted_key = URL_SAFE_NO_PAD.decode(&credential.encrypted_key)
            .map_err(|e| WalletError::Storage(format!("Invalid encrypted key: {}", e)))?;
        
        let decrypted = cipher.decrypt(nonce, encrypted_key.as_ref())
            .map_err(|_| WalletError::Storage("Biometric verification failed".to_string()))?;
        
        let mut wallet_key = [0u8; 32];
        if decrypted.len() == 32 {
            wallet_key.copy_from_slice(&decrypted);
            Ok(wallet_key)
        } else {
            Err(WalletError::Storage("Invalid key length".to_string()))
        }
    }
}

#[cfg(feature = "wasm")]
pub struct WebAuthnManager;

#[cfg(feature = "wasm")]
impl WebAuthnManager {
    /// Register a new biometric credential
    pub async fn register_credential(
        rp_name: &str,
        user_name: &str,
        challenge: &BiometricChallenge,
    ) -> Result<String, WalletError> {
        let window = window().ok_or_else(|| WalletError::Storage("No window available".to_string()))?;
        let navigator = window.navigator();
        let credentials = navigator.credentials()
            .ok_or_else(|| WalletError::Storage("WebAuthn not supported".to_string()))?;
        
        // Create credential creation options
        let options = Self::create_registration_options(rp_name, user_name, challenge)?;
        
        // Call navigator.credentials.create()
        let promise = credentials.create_with_options(&options)
            .map_err(|e| WalletError::Storage(format!("Failed to create credential: {:?}", e)))?;
        
        // Convert to Future and await
        let credential = wasm_bindgen_futures::JsFuture::from(promise)
            .await
            .map_err(|e| WalletError::Storage(format!("Credential creation failed: {:?}", e)))?;
        
        // Extract credential ID
        let credential_id = Self::extract_credential_id(&credential)?;
        Ok(credential_id)
    }
    
    /// Authenticate with existing biometric credential
    pub async fn authenticate_credential(
        credential_id: &str,
        challenge: &BiometricChallenge,
    ) -> Result<String, WalletError> {
        let window = window().ok_or_else(|| WalletError::Storage("No window available".to_string()))?;
        let navigator = window.navigator();
        let credentials = navigator.credentials()
            .ok_or_else(|| WalletError::Storage("WebAuthn not supported".to_string()))?;
        
        // Create credential request options
        let options = Self::create_authentication_options(credential_id, challenge)?;
        
        // Call navigator.credentials.get()
        let promise = credentials.get_with_options(&options)
            .map_err(|e| WalletError::Storage(format!("Failed to get credential: {:?}", e)))?;
        
        // Convert to Future and await
        let credential = wasm_bindgen_futures::JsFuture::from(promise)
            .await
            .map_err(|e| WalletError::Storage(format!("Authentication failed: {:?}", e)))?;
        
        // Verify and return challenge response
        Self::verify_authentication_response(&credential, challenge)
    }
    
    fn create_registration_options(
        rp_name: &str,
        user_name: &str,
        challenge: &BiometricChallenge,
    ) -> Result<Object, WalletError> {
        // This is a simplified version - in practice you'd use web-sys bindings
        // to create proper PublicKeyCredentialCreationOptions
        let options = Object::new();
        
        // Set challenge
        let challenge_bytes = URL_SAFE_NO_PAD.decode(&challenge.challenge)
            .map_err(|e| WalletError::Storage(format!("Invalid challenge: {}", e)))?;
        let challenge_array = Uint8Array::from(&challenge_bytes[..]);
        
        // Use js_sys reflection to set properties
        js_sys::Reflect::set(&options, &"challenge".into(), &challenge_array.into())
            .map_err(|e| WalletError::Storage(format!("Failed to set challenge: {:?}", e)))?;
        
        Ok(options)
    }
    
    fn create_authentication_options(
        credential_id: &str,
        challenge: &BiometricChallenge,
    ) -> Result<Object, WalletError> {
        let options = Object::new();
        
        // Set challenge
        let challenge_bytes = URL_SAFE_NO_PAD.decode(&challenge.challenge)
            .map_err(|e| WalletError::Storage(format!("Invalid challenge: {}", e)))?;
        let challenge_array = Uint8Array::from(&challenge_bytes[..]);
        
        js_sys::Reflect::set(&options, &"challenge".into(), &challenge_array.into())
            .map_err(|e| WalletError::Storage(format!("Failed to set challenge: {:?}", e)))?;
        
        Ok(options)
    }
    
    fn extract_credential_id(credential: &JsValue) -> Result<String, WalletError> {
        // Extract credential ID from the credential response
        // This is simplified - actual implementation would properly parse the response
        Ok("dummy_credential_id".to_string())
    }
    
    fn verify_authentication_response(
        credential: &JsValue,
        challenge: &BiometricChallenge,
    ) -> Result<String, WalletError> {
        // Verify the authentication response
        // This is simplified - actual implementation would verify the signature
        Ok(challenge.challenge.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_biometric_challenge_generation() {
        let challenge = BiometricChallenge::new().unwrap();
        
        assert!(!challenge.challenge.is_empty());
        assert_eq!(challenge.timeout, 60000);
        assert_eq!(challenge.user_verification, "required");
        
        // Should be different each time
        let challenge2 = BiometricChallenge::new().unwrap();
        assert_ne!(challenge.challenge, challenge2.challenge);
    }
    
    #[test]
    fn test_key_encryption_and_decryption() {
        let wallet_key = [42u8; 32];
        let challenge = "test_challenge_string";
        
        // Encrypt key
        let credential = BiometricManager::encrypt_key_for_biometric(&wallet_key, challenge).unwrap();
        
        // Decrypt key
        let decrypted_key = BiometricManager::decrypt_key_with_biometric(&credential, challenge).unwrap();
        
        assert_eq!(wallet_key, decrypted_key);
    }
    
    #[test]
    fn test_wrong_challenge_fails() {
        let wallet_key = [42u8; 32];
        let correct_challenge = "correct_challenge";
        let wrong_challenge = "wrong_challenge";
        
        // Encrypt with correct challenge
        let credential = BiometricManager::encrypt_key_for_biometric(&wallet_key, correct_challenge).unwrap();
        
        // Try to decrypt with wrong challenge
        let result = BiometricManager::decrypt_key_with_biometric(&credential, wrong_challenge);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_is_available_non_wasm() {
        // In non-WASM environment, should return false
        assert!(!BiometricManager::is_available());
    }
    
    #[test]
    fn test_credential_serialization() {
        let wallet_key = [42u8; 32];
        let challenge = "test_challenge";
        
        let credential = BiometricManager::encrypt_key_for_biometric(&wallet_key, challenge).unwrap();
        
        // Test serialization
        let serialized = serde_json::to_string(&credential).unwrap();
        let deserialized: BiometricCredential = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(credential.credential_id, deserialized.credential_id);
        assert_eq!(credential.encrypted_key, deserialized.encrypted_key);
        assert_eq!(credential.salt, deserialized.salt);
    }
}