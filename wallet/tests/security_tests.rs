mod common;

use std::collections::HashSet;
use std::time::Instant;
use proptest::prelude::*;
use test_case::test_case;
use consistenttime::ct_u8_slice_eq;
use wallet::{Seed, UnifiedAccount, Address};
use common::*;

#[test]
fn test_mnemonic_generation_entropy() {
    let mut seeds = HashSet::new();
    for _ in 0..100 {
        let seed = Seed::generate(12).unwrap();
        let phrase = seed.phrase();
        assert!(!seeds.contains(&phrase), "Duplicate mnemonic generated");
        seeds.insert(phrase);
    }
}

#[test_case(12; "12 words")]
#[test_case(15; "15 words")]
#[test_case(18; "18 words")]
#[test_case(21; "21 words")]
#[test_case(24; "24 words")]
fn test_mnemonic_word_counts(word_count: usize) {
    let seed = Seed::generate(word_count).unwrap();
    let phrase = seed.phrase();
    assert_eq!(phrase.split_whitespace().count(), word_count);
}

#[test]
fn test_seed_roundtrip() {
    let original_seed = Seed::generate(12).unwrap();
    let phrase = original_seed.phrase();
    let recovered_seed = Seed::from_phrase(&phrase).unwrap();
    
    let original_bytes = original_seed.to_seed_bytes();
    let recovered_bytes = recovered_seed.to_seed_bytes();
    
    assert!(ct_u8_slice_eq(&original_bytes, &recovered_bytes));
}

#[test]
fn test_passphrase_affects_seed() {
    let seed1 = Seed::from_phrase(TEST_MNEMONIC_12).unwrap();
    let seed2 = Seed::from_phrase(TEST_MNEMONIC_12).unwrap()
        .with_passphrase("test".to_string());
    
    let bytes1 = seed1.to_seed_bytes();
    let bytes2 = seed2.to_seed_bytes();
    
    assert!(!ct_u8_slice_eq(&bytes1, &bytes2));
}

#[test]
fn test_deterministic_account_generation() {
    let seed = create_test_seed().unwrap();
    
    let account1 = UnifiedAccount::derive(&seed, 0, 0).unwrap();
    let account2 = UnifiedAccount::derive(&seed, 0, 0).unwrap();
    
    assert_eq!(account1.blockchain_address, account2.blockchain_address);
    assert_eq!(account1.peer_id, account2.peer_id);
}

#[test]
fn test_account_isolation() {
    let seed = create_test_seed().unwrap();
    
    let account1 = UnifiedAccount::derive(&seed, 0, 0).unwrap();
    let account2 = UnifiedAccount::derive(&seed, 0, 1).unwrap();
    let account3 = UnifiedAccount::derive(&seed, 1, 0).unwrap();
    
    assert_ne!(account1.blockchain_address, account2.blockchain_address);
    assert_ne!(account1.blockchain_address, account3.blockchain_address);
    assert_ne!(account2.blockchain_address, account3.blockchain_address);
    
    assert_ne!(account1.peer_id, account2.peer_id);
    assert_ne!(account1.peer_id, account3.peer_id);
    assert_ne!(account2.peer_id, account3.peer_id);
}

#[test]
fn test_address_prefix() {
    let seed = create_test_seed().unwrap();
    let account = UnifiedAccount::derive(&seed, 0, 0).unwrap();
    
    assert!(account.blockchain_address.starts_with("art"));
}

#[test]
fn test_address_validation() {
    let seed = create_test_seed().unwrap();
    let account = UnifiedAccount::derive(&seed, 0, 0).unwrap();
    
    assert!(Address::validate(&account.blockchain_address).unwrap());
    assert!(!Address::validate("invalid_address").unwrap());
    assert!(!Address::validate("btc1invalid").unwrap());
}

#[test]
fn test_private_key_security() {
    let seed = create_test_seed().unwrap();
    let account = UnifiedAccount::derive(&seed, 0, 0).unwrap();
    
    let private_key = account.blockchain_private_key().unwrap();
    
    assert_ne!(private_key, [0u8; 32]);
    assert!(private_key.iter().any(|&x| x != 0));
}

#[test]
fn test_timing_attack_resistance() {
    let valid_address = {
        let seed = create_test_seed().unwrap();
        let account = UnifiedAccount::derive(&seed, 0, 0).unwrap();
        account.blockchain_address
    };
    
    let invalid_address = "artinvalidaddresstest";
    
    let mut valid_times = Vec::new();
    let mut invalid_times = Vec::new();
    
    for _ in 0..100 {
        let start = Instant::now();
        let _ = Address::validate(&valid_address);
        valid_times.push(start.elapsed());
        
        let start = Instant::now();
        let _ = Address::validate(invalid_address);
        invalid_times.push(start.elapsed());
    }
    
    let valid_avg: f64 = valid_times.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / valid_times.len() as f64;
    let invalid_avg: f64 = invalid_times.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / invalid_times.len() as f64;
    
    let ratio = if valid_avg > invalid_avg {
        valid_avg / invalid_avg
    } else {
        invalid_avg / valid_avg
    };
    
    assert!(ratio < 2.0, "Timing difference too large: {}", ratio);
}

proptest! {
    #[test]
    fn prop_entropy_to_seed_consistent(entropy in prop::collection::vec(any::<u8>(), 16..=32)) {
        if entropy.len() % 4 == 0 {
            let seed1 = Seed::from_entropy(&entropy);
            let seed2 = Seed::from_entropy(&entropy);
            
            if let (Ok(s1), Ok(s2)) = (seed1, seed2) {
                let bytes1 = s1.to_seed_bytes();
                let bytes2 = s2.to_seed_bytes();
                prop_assert!(ct_u8_slice_eq(&bytes1, &bytes2));
            }
        }
    }
    
    #[test]
    fn prop_account_uniqueness(account_num in 0u32..100, index in 0u32..100) {
        let seed = create_test_seed().unwrap();
        let account = UnifiedAccount::derive(&seed, account_num, index).unwrap();
        
        prop_assert!(account.blockchain_address.starts_with("art"));
        prop_assert!(account.index == index);
        prop_assert!(account.account_number == account_num);
    }
    
    #[test]
    fn prop_address_validation_consistency(
        valid_chars in "[a-zA-Z0-9]{20,50}",
        prefix in "(art|btc|eth)"
    ) {
        let test_address = format!("{}{}", prefix, valid_chars);
        let result1 = Address::validate(&test_address);
        let result2 = Address::validate(&test_address);
        
        prop_assert_eq!(result1.is_ok(), result2.is_ok());
        if let (Ok(r1), Ok(r2)) = (result1, result2) {
            prop_assert_eq!(r1, r2);
        }
    }
}