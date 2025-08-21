use serde::{Serialize, Deserialize};
use crate::{
    error::WalletError,
    seed::Seed,
    derivation::{KeyDerivation, DerivedKey, Ed25519DerivedKey},
    address::Address,
    identity::P2PIdentity,
};

#[derive(Serialize, Deserialize)]
pub struct UnifiedAccount {
    pub index: u32,
    pub account_number: u32,
    pub blockchain_address: String,
    pub peer_id: String,
    #[serde(skip)]
    blockchain_key: Option<DerivedKey>,
    #[serde(skip)]
    ed25519_key: Option<Ed25519DerivedKey>,
    #[serde(skip)]
    p2p_identity: Option<P2PIdentity>,
}

impl UnifiedAccount {
    pub fn derive(seed: &Seed, account_number: u32, index: u32) -> Result<Self, WalletError> {
        let seed_bytes = seed.to_seed_bytes();
        let derivation = KeyDerivation::from_seed(&seed_bytes)?;
        
        // Derive blockchain key
        let blockchain_key = derivation.derive_blockchain_key(account_number, index)?;
        let public_key_bytes = blockchain_key.public_key_bytes();
        let address = Address::from_public_key(&public_key_bytes)?;
        
        // Derive ed25519 key for P2P with same index
        let ed25519_key = derivation.derive_ed25519_key(account_number, index)?;
        
        // Create P2P identity from ed25519 key
        let p2p_identity = P2PIdentity::from_ed25519_key(&ed25519_key)?;
        
        Ok(Self {
            index,
            account_number,
            blockchain_address: address.to_string(),
            peer_id: p2p_identity.peer_id_string(),
            blockchain_key: Some(blockchain_key),
            ed25519_key: Some(ed25519_key),
            p2p_identity: Some(p2p_identity),
        })
    }
    
    pub fn blockchain_private_key(&self) -> Option<[u8; 32]> {
        self.blockchain_key.as_ref().map(|k| k.private_key_bytes())
    }
    
    pub fn blockchain_public_key(&self) -> Option<[u8; 33]> {
        self.blockchain_key.as_ref().map(|k| k.public_key_bytes())
    }
    
    pub fn ed25519_signing_key(&self) -> Option<&ed25519_dalek::SigningKey> {
        self.ed25519_key.as_ref().map(|k| &k.signing_key)
    }
    
    pub fn ed25519_derived_key(&self) -> Option<&Ed25519DerivedKey> {
        self.ed25519_key.as_ref()
    }
    
    pub fn ed25519_public_key(&self) -> Option<[u8; 32]> {
        self.ed25519_key.as_ref().map(|k| k.public_key_bytes())
    }
    
    pub fn p2p_identity(&self) -> Option<&P2PIdentity> {
        self.p2p_identity.as_ref()
    }
}

pub struct Wallet {
    seed: Seed,
    accounts: Vec<UnifiedAccount>,
}

impl Wallet {
    pub fn new(seed: Seed) -> Self {
        Self {
            seed,
            accounts: Vec::new(),
        }
    }
    
    pub fn from_mnemonic(phrase: &str, passphrase: Option<String>) -> Result<Self, WalletError> {
        let mut seed = Seed::from_phrase(phrase)?;
        if let Some(pass) = passphrase {
            seed = seed.with_passphrase(pass);
        }
        Ok(Self::new(seed))
    }
    
    pub fn generate_account(&mut self, account_number: u32, index: u32) -> Result<&UnifiedAccount, WalletError> {
        let account = UnifiedAccount::derive(&self.seed, account_number, index)?;
        self.accounts.push(account);
        Ok(self.accounts.last().unwrap())
    }
    
    pub fn get_account(&self, index: u32) -> Option<&UnifiedAccount> {
        self.accounts.iter().find(|a| a.index == index)
    }
    
    pub fn accounts(&self) -> &[UnifiedAccount] {
        &self.accounts
    }
}