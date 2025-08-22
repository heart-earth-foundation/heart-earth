// Test to verify WASM wallet produces identical results to CLI wallet

use wallet::{Seed, UnifiedAccount};
use wasm::wasm_wallet::WasmWallet;

#[test]
fn test_wasm_cli_compatibility() {
    // Use a known test mnemonic
    let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let account_number = 0;
    let index = 0;
    
    // Generate account using CLI wallet
    let seed = Seed::from_phrase(test_mnemonic).expect("Valid mnemonic");
    let cli_account = UnifiedAccount::derive(&seed, account_number, index).expect("CLI derivation failed");
    
    // Generate account using WASM wallet  
    let wasm_account = WasmWallet::create_account(test_mnemonic, account_number, index).expect("WASM derivation failed");
    
    // Compare addresses
    println!("CLI blockchain address: {}", cli_account.blockchain_address);
    println!("WASM blockchain address: {}", wasm_account.blockchain_address);
    
    println!("CLI peer ID: {}", cli_account.peer_id);
    println!("WASM peer ID: {}", wasm_account.peer_id);
    
    // They should be identical
    assert_eq!(cli_account.blockchain_address, wasm_account.blockchain_address, 
               "Blockchain addresses must match between CLI and WASM");
    
    assert_eq!(cli_account.peer_id, wasm_account.peer_id,
               "Peer IDs must match between CLI and WASM");
}

#[test]
fn test_mnemonic_generation() {
    // Test that both generate valid mnemonics
    let cli_mnemonic = wallet::Seed::generate(12).expect("CLI mnemonic generation failed").phrase();
    let wasm_mnemonic = WasmWallet::generate_mnemonic().expect("WASM mnemonic generation failed");
    
    println!("CLI generated: {}", cli_mnemonic);
    println!("WASM generated: {}", wasm_mnemonic);
    
    // Both should be valid BIP39 mnemonics (12 words)
    assert_eq!(cli_mnemonic.split_whitespace().count(), 12);
    assert_eq!(wasm_mnemonic.split_whitespace().count(), 12);
    
    // Should be able to derive accounts from both
    let _cli_from_wasm = wallet::Seed::from_phrase(&wasm_mnemonic).expect("WASM mnemonic should be valid for CLI");
    let _wasm_from_cli = WasmWallet::create_account(&cli_mnemonic, 0, 0).expect("CLI mnemonic should be valid for WASM");
}