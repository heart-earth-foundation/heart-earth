use thiserror::Error;

#[derive(Error, Debug)]
pub enum P2PError {
    #[error("Transport error: {0}")]
    Transport(String),
    
    #[error("Identity error: {0}")]
    Identity(String),
    
    #[error("Network behaviour error: {0}")]
    Behaviour(String),
    
    #[error("Message error: {0}")]
    Message(String),
    
    #[error("Wallet error: {0}")]
    Wallet(#[from] wallet::WalletError),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}