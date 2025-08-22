use wallet::{Seed, WalletError};

pub const TEST_MNEMONIC_12: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
pub const TEST_MNEMONIC_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

pub const TEST_ENTROPY_128: [u8; 16] = [0u8; 16];
pub const TEST_ENTROPY_256: [u8; 32] = [0u8; 32];

pub fn create_test_seed() -> Result<Seed, WalletError> {
    Seed::from_phrase(TEST_MNEMONIC_12)
}

#[allow(dead_code)]
pub fn create_test_seed_with_passphrase(passphrase: &str) -> Result<Seed, WalletError> {
    let seed = Seed::from_phrase(TEST_MNEMONIC_12)?;
    Ok(seed.with_passphrase(passphrase.to_string()))
}