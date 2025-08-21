pub mod error;
pub mod seed;
pub mod derivation;
pub mod account;
pub mod address;
pub mod identity;

pub use error::WalletError;
pub use seed::Seed;
pub use account::{UnifiedAccount, Wallet};
pub use address::Address;