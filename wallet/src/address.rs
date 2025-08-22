use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use bs58;
use consistenttime::ct_u8_slice_eq;
use crate::error::WalletError;

const PREFIX: &str = "heart";
const VERSION_BYTE: u8 = 0x41; // Custom version byte for 'heart' addresses

pub struct Address {
    raw: Vec<u8>,
    encoded: String,
}

impl Address {
    pub fn from_public_key(public_key: &[u8; 33]) -> Result<Self, WalletError> {
        // SHA256 of public key
        let sha256 = Sha256::digest(public_key);
        
        // RIPEMD160 of SHA256
        use ripemd::Digest as RipemdDigest;
        let hash160 = Ripemd160::digest(&sha256);
        
        // Add version byte
        let mut versioned = vec![VERSION_BYTE];
        versioned.extend_from_slice(&hash160);
        
        // Calculate checksum (double SHA256)
        let checksum = Self::calculate_checksum(&versioned);
        
        // Append checksum
        let mut raw = versioned;
        raw.extend_from_slice(&checksum[..4]);
        
        // Base58 encode with prefix
        let base58_encoded = bs58::encode(&raw).into_string();
        let encoded = format!("{}{}", PREFIX, base58_encoded);
        
        Ok(Self { raw, encoded })
    }
    
    fn calculate_checksum(data: &[u8]) -> [u8; 32] {
        let first_hash = Sha256::digest(data);
        let second_hash = Sha256::digest(&first_hash);
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&second_hash);
        checksum
    }
    
    pub fn to_string(&self) -> String {
        self.encoded.clone()
    }
    
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
    
    pub fn validate(address: &str) -> Result<bool, WalletError> {
        // Always perform the same operations regardless of input
        let mut prefix_bytes = [0u8; 8]; // Increased buffer to handle "heart"
        let mut input_prefix = [0u8; 8];
        
        prefix_bytes[..PREFIX.len()].copy_from_slice(PREFIX.as_bytes());
        
        // Copy input prefix, padding with zeros if too short
        let copy_len = std::cmp::min(address.len(), PREFIX.len());
        if copy_len > 0 {
            input_prefix[..copy_len].copy_from_slice(&address.as_bytes()[..copy_len]);
        }
        
        let prefix_match = ct_u8_slice_eq(&prefix_bytes, &input_prefix);
        
        // Always attempt to decode, even if prefix doesn't match
        let without_prefix = if address.len() > PREFIX.len() {
            &address[PREFIX.len()..]
        } else {
            ""
        };
        
        // Always attempt base58 decode
        let decoded = match bs58::decode(without_prefix).into_vec() {
            Ok(data) => data,
            Err(_) => vec![0u8; 25], // Use dummy data if decode fails
        };
        
        // Pad to minimum length if needed
        let mut padded_decoded = vec![0u8; 25];
        let copy_len = std::cmp::min(decoded.len(), padded_decoded.len());
        padded_decoded[..copy_len].copy_from_slice(&decoded[..copy_len]);
        
        let length_valid = decoded.len() >= 25;
        
        // Always compute checksum
        let (versioned, provided_checksum) = if decoded.len() >= 25 {
            decoded.split_at(decoded.len() - 4)
        } else {
            ([0u8; 21].as_slice(), [0u8; 4].as_slice())
        };
        
        let calculated_checksum = Self::calculate_checksum(versioned);
        let checksum_valid = ct_u8_slice_eq(&calculated_checksum[..4], provided_checksum);
        
        Ok(prefix_match && length_valid && checksum_valid)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encoded)
    }
}