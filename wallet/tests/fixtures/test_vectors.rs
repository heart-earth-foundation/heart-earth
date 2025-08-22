pub struct TestVector {
    pub mnemonic: &'static str,
    pub passphrase: &'static str,
    pub seed_hex: &'static str,
    pub account: u32,
    pub index: u32,
    pub expected_private_key: &'static str,
    pub expected_address: &'static str,
}

pub const BIP32_TEST_VECTORS: &[TestVector] = &[
    TestVector {
        mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        passphrase: "",
        seed_hex: "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4e13f",
        account: 0,
        index: 0,
        expected_private_key: "TODO",
        expected_address: "TODO",
    },
];

pub const ENTROPY_TEST_VECTORS: &[(&[u8], &str)] = &[
    (&[0u8; 16], "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
    (&[0xff; 16], "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"),
];

pub const INVALID_MNEMONICS: &[&str] = &[
    "",
    "abandon",
    "abandon abandon",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
    "invalid word word word word word word word word word word word",
];

pub const INVALID_ADDRESSES: &[&str] = &[
    "",
    "invalid",
    "btc1invalid",
    "heart", // Too short
    "heartinvalidchecksum123456789",
];

pub const TIMING_ATTACK_TEST_CASES: &[(&str, &str)] = &[
    ("valid_short", "heart123"),
    ("valid_long", "heart1234567890abcdef"),
    ("invalid_short", "xxx123"),
    ("invalid_long", "xxx1234567890abcdef"),
    ("wrong_prefix", "btc1234567890abcdef"),
];