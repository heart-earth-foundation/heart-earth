use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use crate::error::WalletError;

const AES_NONCE_SIZE: usize = 12;

pub struct X25519KeyPair {
    secret: StaticSecret,
    public_key: X25519PublicKey,
}

impl X25519KeyPair {
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public_key
    }
    
    pub fn compute_shared_secret(&self, their_public: &X25519PublicKey) -> [u8; 32] {
        *self.secret.diffie_hellman(their_public).as_bytes()
    }
}

pub struct EncryptionManager;

impl EncryptionManager {
    pub fn derive_x25519_keypair_from_ed25519(ed25519_secret: &[u8; 32]) -> Result<X25519KeyPair, WalletError> {
        let secret = StaticSecret::from(*ed25519_secret);
        let public_key = X25519PublicKey::from(&secret);
        
        Ok(X25519KeyPair {
            secret,
            public_key,
        })
    }
    
    pub fn derive_channel_key(shared_secret: &[u8; 32], channel_id: &str) -> Key<Aes256Gcm> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(channel_id.as_bytes());
        
        let key_bytes = hasher.finalize();
        *Key::<Aes256Gcm>::from_slice(&key_bytes)
    }
    
    pub fn encrypt_message(
        message: &str,
        key: &Key<Aes256Gcm>
    ) -> Result<(Vec<u8>, [u8; AES_NONCE_SIZE]), WalletError> {
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        let ciphertext = cipher.encrypt(&nonce, message.as_bytes())
            .map_err(|e| WalletError::Encryption(format!("Failed to encrypt message: {}", e)))?;
        
        let nonce_array: [u8; AES_NONCE_SIZE] = nonce.as_slice().try_into()
            .map_err(|_| WalletError::Encryption("Invalid nonce size".to_string()))?;
        
        Ok((ciphertext, nonce_array))
    }
    
    pub fn decrypt_message(
        ciphertext: &[u8],
        nonce: &[u8; AES_NONCE_SIZE],
        key: &Key<Aes256Gcm>
    ) -> Result<String, WalletError> {
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| WalletError::Encryption(format!("Failed to decrypt message: {}", e)))?;
        
        String::from_utf8(plaintext)
            .map_err(|e| WalletError::Encryption(format!("Invalid UTF-8 in decrypted message: {}", e)))
    }
    
    pub fn x25519_public_key_to_bytes(public_key: &X25519PublicKey) -> [u8; 32] {
        *public_key.as_bytes()
    }
    
    pub fn x25519_public_key_from_bytes(bytes: &[u8; 32]) -> X25519PublicKey {
        X25519PublicKey::from(*bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};
    
    #[test]
    fn test_ed25519_to_x25519_conversion() {
        let mut ed25519_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut ed25519_bytes);
        
        let result = EncryptionManager::derive_x25519_keypair_from_ed25519(&ed25519_bytes);
        assert!(result.is_ok());
        
        let x25519_keypair = result.unwrap();
        assert_eq!(x25519_keypair.public_key().as_bytes().len(), 32);
    }
    
    #[test]
    fn test_key_exchange() {
        let mut alice_ed25519_bytes = [0u8; 32];
        let mut bob_ed25519_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut alice_ed25519_bytes);
        OsRng.fill_bytes(&mut bob_ed25519_bytes);
        
        let alice_keypair = EncryptionManager::derive_x25519_keypair_from_ed25519(&alice_ed25519_bytes).unwrap();
        let bob_keypair = EncryptionManager::derive_x25519_keypair_from_ed25519(&bob_ed25519_bytes).unwrap();
        
        let alice_shared = alice_keypair.compute_shared_secret(bob_keypair.public_key());
        let bob_shared = bob_keypair.compute_shared_secret(alice_keypair.public_key());
        
        assert_eq!(alice_shared, bob_shared);
    }
    
    #[test]
    fn test_encryption_decryption() {
        let mut alice_ed25519_bytes = [0u8; 32];
        let mut bob_ed25519_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut alice_ed25519_bytes);
        OsRng.fill_bytes(&mut bob_ed25519_bytes);
        
        let alice_keypair = EncryptionManager::derive_x25519_keypair_from_ed25519(&alice_ed25519_bytes).unwrap();
        let bob_keypair = EncryptionManager::derive_x25519_keypair_from_ed25519(&bob_ed25519_bytes).unwrap();
        
        let alice_shared = alice_keypair.compute_shared_secret(bob_keypair.public_key());
        let bob_shared = bob_keypair.compute_shared_secret(alice_keypair.public_key());
        
        let channel_id = "test_channel";
        let alice_key = EncryptionManager::derive_channel_key(&alice_shared, channel_id);
        let bob_key = EncryptionManager::derive_channel_key(&bob_shared, channel_id);
        
        let message = "Hello, secure world!";
        let (ciphertext, nonce) = EncryptionManager::encrypt_message(message, &alice_key).unwrap();
        let decrypted = EncryptionManager::decrypt_message(&ciphertext, &nonce, &bob_key).unwrap();
        
        assert_eq!(message, decrypted);
    }
    
    #[test]
    fn test_channel_key_derivation() {
        let mut alice_ed25519_bytes = [0u8; 32];
        let mut bob_ed25519_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut alice_ed25519_bytes);
        OsRng.fill_bytes(&mut bob_ed25519_bytes);
        
        let alice_keypair = EncryptionManager::derive_x25519_keypair_from_ed25519(&alice_ed25519_bytes).unwrap();
        let bob_keypair = EncryptionManager::derive_x25519_keypair_from_ed25519(&bob_ed25519_bytes).unwrap();
        
        let alice_shared = alice_keypair.compute_shared_secret(bob_keypair.public_key());
        let bob_shared = bob_keypair.compute_shared_secret(alice_keypair.public_key());
        
        let channel1_alice = EncryptionManager::derive_channel_key(&alice_shared, "channel1");
        let channel1_bob = EncryptionManager::derive_channel_key(&bob_shared, "channel1");
        let channel2_alice = EncryptionManager::derive_channel_key(&alice_shared, "channel2");
        
        assert_eq!(channel1_alice, channel1_bob);
        assert_ne!(channel1_alice, channel2_alice);
    }
    
    #[test]
    fn test_public_key_serialization() {
        let mut ed25519_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut ed25519_bytes);
        let keypair = EncryptionManager::derive_x25519_keypair_from_ed25519(&ed25519_bytes).unwrap();
        
        let bytes = EncryptionManager::x25519_public_key_to_bytes(keypair.public_key());
        let reconstructed = EncryptionManager::x25519_public_key_from_bytes(&bytes);
        
        assert_eq!(keypair.public_key().as_bytes(), reconstructed.as_bytes());
    }
}