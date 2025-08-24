use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("BIP32 error: {0}")]
    Bip32(#[from] bip32::Error),
    
    #[error("BIP39 error: {0}")]
    Bip39(#[from] bip39::Error),
    
    #[error("Invalid derivation path: {0}")]
    InvalidPath(String),
    
    #[error("Secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
    
    #[error("Invalid entropy length: expected {expected}, got {got}")]
    InvalidEntropyLength { expected: usize, got: usize },
    
    #[error("Address generation failed: {0}")]
    AddressGeneration(String),
    
    #[error("P2P identity error: {0}")]
    P2PIdentity(String),
    
    #[error("Storage error: {0}")]
    Storage(String),
    
    #[error("Encryption error: {0}")]
    Encryption(String),
}