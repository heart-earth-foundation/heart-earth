use bip39::{Mnemonic, Language};
use crate::error::WalletError;

pub struct Seed {
    mnemonic: Mnemonic,
    passphrase: String,
}

impl Seed {
    pub fn generate(word_count: usize) -> Result<Self, WalletError> {
        let mnemonic = Mnemonic::generate(word_count)?;
        Ok(Self {
            mnemonic,
            passphrase: String::new(),
        })
    }
    
    pub fn from_phrase(phrase: &str) -> Result<Self, WalletError> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)?;
        Ok(Self {
            mnemonic,
            passphrase: String::new(),
        })
    }
    
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, WalletError> {
        let mnemonic = Mnemonic::from_entropy(entropy)?;
        Ok(Self {
            mnemonic,
            passphrase: String::new(),
        })
    }
    
    pub fn with_passphrase(mut self, passphrase: String) -> Self {
        self.passphrase = passphrase;
        self
    }
    
    pub fn to_seed_bytes(&self) -> [u8; 64] {
        self.mnemonic.to_seed(&self.passphrase)
    }
    
    pub fn phrase(&self) -> String {
        self.mnemonic.to_string()
    }
    
    pub fn entropy(&self) -> Vec<u8> {
        self.mnemonic.to_entropy()
    }
}