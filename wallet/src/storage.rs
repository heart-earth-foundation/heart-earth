use std::fs;
use std::path::PathBuf;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use argon2::Argon2;
use argon2::password_hash::rand_core::RngCore;
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, Zeroizing};
use crate::error::WalletError;

const WALLET_VERSION: u8 = 1;
const SALT_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

#[derive(Serialize, Deserialize)]
pub struct EncryptedWallet {
    version: u8,
    created_at: u64,
    salt: [u8; SALT_SIZE],
    nonce: [u8; NONCE_SIZE],
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
struct WalletData {
    mnemonic: String,
    created_at: u64,
}

pub struct WalletStorage;

impl WalletStorage {
    pub fn get_wallet_path(name: &str) -> Result<PathBuf, WalletError> {
        let config_dir = dirs::config_dir()
            .or_else(|| dirs::data_local_dir())
            .ok_or_else(|| WalletError::Storage("No config directory found".to_string()))?;
        
        let wallet_dir = config_dir.join("heart-earth").join("wallets");
        fs::create_dir_all(&wallet_dir)
            .map_err(|e| WalletError::Storage(format!("Failed to create wallet directory: {}", e)))?;
        
        Ok(wallet_dir.join(format!("{}.wallet", name)))
    }
    
    pub fn save_encrypted_wallet(
        name: &str,
        mnemonic: &str,
        password: &Zeroizing<String>
    ) -> Result<(), WalletError> {
        Self::validate_password(password)?;
        let wallet_path = Self::get_wallet_path(name)?;
        
        let mut salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        
        let key = Self::derive_key(password, &salt)?;
        
        let wallet_data = WalletData {
            mnemonic: mnemonic.to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        let plaintext = serde_json::to_vec(&wallet_data)
            .map_err(|e| WalletError::Storage(format!("Serialization failed: {}", e)))?;
        
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| WalletError::Storage(format!("Encryption failed: {}", e)))?;
        
        let encrypted_wallet = EncryptedWallet {
            version: WALLET_VERSION,
            created_at: wallet_data.created_at,
            salt,
            nonce: nonce.into(),
            ciphertext,
        };
        
        let wallet_json = serde_json::to_string_pretty(&encrypted_wallet)
            .map_err(|e| WalletError::Storage(format!("JSON serialization failed: {}", e)))?;
        
        fs::write(&wallet_path, wallet_json)
            .map_err(|e| WalletError::Storage(format!("Failed to write wallet file: {}", e)))?;
        
        Ok(())
    }
    
    pub fn load_encrypted_wallet(
        name: &str,
        password: &Zeroizing<String>
    ) -> Result<String, WalletError> {
        Self::validate_password(password)?;
        let wallet_path = Self::get_wallet_path(name)?;
        
        if !wallet_path.exists() {
            return Err(WalletError::Storage(format!("Wallet '{}' not found", name)));
        }
        
        let wallet_json = fs::read_to_string(&wallet_path)
            .map_err(|e| WalletError::Storage(format!("Failed to read wallet file: {}", e)))?;
        
        let encrypted_wallet: EncryptedWallet = serde_json::from_str(&wallet_json)
            .map_err(|e| WalletError::Storage(format!("Failed to parse wallet file: {}", e)))?;
        
        if encrypted_wallet.version != WALLET_VERSION {
            return Err(WalletError::Storage(format!(
                "Unsupported wallet version: {}", encrypted_wallet.version
            )));
        }
        
        let key = Self::derive_key(password, &encrypted_wallet.salt)?;
        
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&encrypted_wallet.nonce);
        
        let plaintext = cipher.decrypt(nonce, encrypted_wallet.ciphertext.as_ref())
            .map_err(|_| WalletError::Storage("Invalid password or corrupted wallet".to_string()))?;
        
        let mut wallet_data: WalletData = serde_json::from_slice(&plaintext)
            .map_err(|e| WalletError::Storage(format!("Failed to deserialize wallet data: {}", e)))?;
        
        let mnemonic = wallet_data.mnemonic.clone();
        wallet_data.zeroize();
        
        Ok(mnemonic)
    }
    
    pub fn wallet_exists(name: &str) -> bool {
        Self::get_wallet_path(name)
            .map(|path| path.exists())
            .unwrap_or(false)
    }
    
    fn derive_key(password: &Zeroizing<String>, salt: &[u8; SALT_SIZE]) -> Result<Key<Aes256Gcm>, WalletError> {
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        
        Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut *key_bytes)
            .map_err(|e| WalletError::Storage(format!("Key derivation failed: {}", e)))?;
        
        Ok(Key::<Aes256Gcm>::from_slice(&*key_bytes).clone())
    }
    
    fn validate_password(password: &Zeroizing<String>) -> Result<(), WalletError> {
        if !password.is_ascii() {
            return Err(WalletError::Storage(
                "Password must contain only ASCII characters (a-z, A-Z, 0-9, symbols). Unicode characters are not allowed for security reasons.".to_string()
            ));
        }
        
        if password.is_empty() {
            return Err(WalletError::Storage(
                "Password cannot be empty".to_string()
            ));
        }
        
        Ok(())
    }
}