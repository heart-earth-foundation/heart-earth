use ed25519_dalek::{SigningKey as Ed25519SigningKey};
use bip39::{Mnemonic, Language};
use bip32::XPrv;
use sha2::{Sha256, Digest};
use std::str::FromStr;
use slip10_ed25519::derive_ed25519_private_key;
use libp2p_identity::{PeerId, Keypair, ed25519};

#[derive(Debug, Clone)]
pub struct WasmAccount {
    pub blockchain_address: String,
    pub peer_id: String,
}

pub struct WasmWallet;

impl WasmWallet {
    pub fn generate_mnemonic() -> Result<String, Box<dyn std::error::Error>> {
        let mnemonic = Mnemonic::generate_in(Language::English, 12)?;
        Ok(mnemonic.to_string())
    }
    
    pub fn create_account(mnemonic: &str, account_number: u32, index: u32) -> Result<WasmAccount, Box<dyn std::error::Error>> {
        // Parse mnemonic
        let mnemonic = Mnemonic::from_str(mnemonic)?;
        let seed = mnemonic.to_seed("");
        
        // Derive secp256k1 key for blockchain address - match CLI exactly
        let secp_path = format!("m/44'/0'/{}'/{}/{}", account_number, 0, index);
        let secp_xprv = XPrv::derive_from_path(&seed, &secp_path.parse()?)?;
        let secp_xpub = secp_xprv.public_key();
        
        // Use XPub bytes directly like CLI does
        let public_key_bytes = secp_xpub.to_bytes(); // This should be [u8; 33] compressed
        let blockchain_address = Self::create_address_from_public_key(&public_key_bytes)?;
        
        // Derive ed25519 key for P2P identity - match CLI exactly (SLIP-0010)
        let indexes = vec![44, 1, account_number, 0, index];
        let ed25519_private_bytes = derive_ed25519_private_key(&seed, &indexes);
        let ed25519_key = Ed25519SigningKey::from_bytes(&ed25519_private_bytes);
        let _ed25519_public = ed25519_key.verifying_key();
        
        // Create libp2p-compatible peer ID from ed25519 private key
        let peer_id = Self::create_peer_id(&ed25519_private_bytes)?;
        
        Ok(WasmAccount {
            blockchain_address,
            peer_id,
        })
    }
    
    fn create_address_from_public_key(public_key: &[u8; 33]) -> Result<String, Box<dyn std::error::Error>> {
        // Create address exactly like CLI
        // SHA256 of public key
        let sha256 = Sha256::digest(public_key);
        
        // RIPEMD160 of SHA256
        use ripemd::Digest as RipemdDigest;
        let hash160 = ripemd::Ripemd160::digest(&sha256);
        
        // Add version byte (CLI uses 0x41)
        let mut versioned = vec![0x41];
        versioned.extend_from_slice(&hash160);
        
        // Calculate checksum (double SHA256) 
        let checksum = Self::calculate_checksum(&versioned);
        
        // Append checksum
        let mut raw = versioned;
        raw.extend_from_slice(&checksum[..4]);
        
        // Base58 encode with prefix
        let base58_encoded = bs58::encode(&raw).into_string();
        let encoded = format!("heart{}", base58_encoded);
        
        Ok(encoded)
    }
    
    fn calculate_checksum(data: &[u8]) -> [u8; 32] {
        let first_hash = Sha256::digest(data);
        let second_hash = Sha256::digest(&first_hash);
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&second_hash);
        checksum
    }
    
    
    fn create_peer_id(ed25519_private_bytes: &[u8; 32]) -> Result<String, Box<dyn std::error::Error>> {
        // Create libp2p peer ID exactly like CLI
        let secret_key = ed25519::SecretKey::try_from_bytes(ed25519_private_bytes.to_vec())?;
        let keypair = ed25519::Keypair::from(secret_key);
        let keypair = Keypair::from(keypair);
        let peer_id = PeerId::from(&keypair.public());
        
        Ok(peer_id.to_string())
    }
}