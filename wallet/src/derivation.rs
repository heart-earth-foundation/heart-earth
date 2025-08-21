use bip32::{XPrv, XPub, DerivationPath};
use slip10_ed25519::derive_ed25519_private_key;
use ed25519_dalek::SigningKey;
use crate::error::WalletError;

pub const PURPOSE: u32 = 44;
pub const BLOCKCHAIN_CHAIN: u32 = 0;
pub const P2P_CHAIN: u32 = 1;

pub struct KeyDerivation {
    seed: [u8; 64],
}

impl KeyDerivation {
    pub fn from_seed(seed: &[u8; 64]) -> Result<Self, WalletError> {
        Ok(Self { seed: *seed })
    }
    
    pub fn derive_blockchain_key(&self, account: u32, index: u32) -> Result<DerivedKey, WalletError> {
        let path = format!("m/{}'/{}'/{}'/{}/{}",
            PURPOSE, BLOCKCHAIN_CHAIN, account, 0, index);
        self.derive(&path)
    }
    
    pub fn derive_ed25519_key(&self, account: u32, index: u32) -> Result<Ed25519DerivedKey, WalletError> {
        let indexes = vec![PURPOSE, P2P_CHAIN, account, 0, index];
        let private_key_bytes = derive_ed25519_private_key(&self.seed, &indexes);
        let signing_key = SigningKey::from_bytes(&private_key_bytes);
        
        Ok(Ed25519DerivedKey {
            signing_key,
            private_key_bytes,
        })
    }
    
    fn derive(&self, path: &str) -> Result<DerivedKey, WalletError> {
        let derivation_path: DerivationPath = path.parse()
            .map_err(|e| WalletError::InvalidPath(format!("{:?}", e)))?;
        
        let child_xprv = XPrv::derive_from_path(&self.seed, &derivation_path)?;
        let child_xpub = child_xprv.public_key();
        
        Ok(DerivedKey {
            private_key: child_xprv,
            public_key: child_xpub,
        })
    }
}

pub struct DerivedKey {
    pub private_key: XPrv,
    pub public_key: XPub,
}

impl DerivedKey {
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.private_key.to_bytes()
    }
    
    pub fn public_key_bytes(&self) -> [u8; 33] {
        self.public_key.to_bytes()
    }
}

pub struct Ed25519DerivedKey {
    pub signing_key: SigningKey,
    pub private_key_bytes: [u8; 32],
}

impl Ed25519DerivedKey {
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }
    
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }
}