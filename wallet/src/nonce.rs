use rand::rngs::OsRng;
use rand::RngCore;
use hex;
use crate::error::WalletError;

const NONCE_SIZE: usize = 32;

#[derive(Clone)]
pub struct Nonce {
    bytes: [u8; NONCE_SIZE],
    hex_string: String,
}

impl Nonce {
    pub fn generate() -> Result<Self, WalletError> {
        let mut bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut bytes);
        
        let hex_string = hex::encode(&bytes);
        
        Ok(Self {
            bytes,
            hex_string,
        })
    }
    
    pub fn from_hex(hex_str: &str) -> Result<Self, WalletError> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| WalletError::Storage(format!("Invalid hex nonce: {}", e)))?;
        
        if bytes.len() != NONCE_SIZE {
            return Err(WalletError::Storage(format!(
                "Invalid nonce length: expected {} bytes, got {}", 
                NONCE_SIZE, 
                bytes.len()
            )));
        }
        
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes.copy_from_slice(&bytes);
        
        let hex_string = hex::encode(&nonce_bytes);
        
        Ok(Self {
            bytes: nonce_bytes,
            hex_string,
        })
    }
    
    pub fn bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.bytes
    }
    
    pub fn hex(&self) -> &str {
        &self.hex_string
    }
    
    pub fn validate(&self, other: &str) -> bool {
        self.hex_string == other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation() {
        let nonce1 = Nonce::generate().unwrap();
        let nonce2 = Nonce::generate().unwrap();
        
        assert_ne!(nonce1.hex(), nonce2.hex());
        assert_eq!(nonce1.bytes().len(), NONCE_SIZE);
        assert_eq!(nonce1.hex().len(), NONCE_SIZE * 2);
    }
    
    #[test]
    fn test_nonce_from_hex() {
        let original = Nonce::generate().unwrap();
        let hex_str = original.hex();
        
        let reconstructed = Nonce::from_hex(hex_str).unwrap();
        
        assert_eq!(original.hex(), reconstructed.hex());
        assert_eq!(original.bytes(), reconstructed.bytes());
    }
    
    #[test]
    fn test_nonce_validation() {
        let nonce = Nonce::generate().unwrap();
        let hex_str = nonce.hex();
        
        assert!(nonce.validate(hex_str));
        assert!(!nonce.validate("invalid"));
    }
    
    #[test]
    fn test_invalid_hex_length() {
        let result = Nonce::from_hex("abc123");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_invalid_hex_format() {
        let invalid_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let result = Nonce::from_hex(invalid_hex);
        assert!(result.is_err());
    }
}