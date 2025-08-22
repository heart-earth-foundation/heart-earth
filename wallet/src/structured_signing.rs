use blake3;
use serde::{Serialize, Deserialize};
use ed25519_dalek::{Signer, Verifier, Signature};
use crate::{
    error::WalletError,
    account::UnifiedAccount,
};

const DOMAIN_SEPARATOR_CONTEXT: &[u8] = b"heart-earth-structured-data";
const TYPE_HASH_CONTEXT: &[u8] = b"heart-earth-type-hash";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainSeparator {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: Option<String>,
    pub salt: Option<String>,
}

impl DomainSeparator {
    pub fn new(name: String, version: String, chain_id: u64) -> Self {
        Self {
            name,
            version,
            chain_id,
            verifying_contract: None,
            salt: None,
        }
    }
    
    pub fn with_contract(mut self, contract: String) -> Self {
        self.verifying_contract = Some(contract);
        self
    }
    
    pub fn with_salt(mut self, salt: String) -> Self {
        self.salt = Some(salt);
        self
    }
    
    fn encode_deterministic(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Encode name
        data.extend_from_slice(&(self.name.len() as u32).to_be_bytes());
        data.extend_from_slice(self.name.as_bytes());
        
        // Encode version
        data.extend_from_slice(&(self.version.len() as u32).to_be_bytes());
        data.extend_from_slice(self.version.as_bytes());
        
        // Encode chain_id
        data.extend_from_slice(&self.chain_id.to_be_bytes());
        
        // Encode optional verifying_contract
        match &self.verifying_contract {
            Some(contract) => {
                data.push(1); // present
                data.extend_from_slice(&(contract.len() as u32).to_be_bytes());
                data.extend_from_slice(contract.as_bytes());
            }
            None => data.push(0), // not present
        }
        
        // Encode optional salt
        match &self.salt {
            Some(salt) => {
                data.push(1); // present
                data.extend_from_slice(&(salt.len() as u32).to_be_bytes());
                data.extend_from_slice(salt.as_bytes());
            }
            None => data.push(0), // not present
        }
        
        data
    }
    
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_SEPARATOR_CONTEXT);
        hasher.update(&self.encode_deterministic());
        *hasher.finalize().as_bytes()
    }
}

pub trait TypedData: Clone {
    fn type_name() -> &'static str;
    fn type_hash() -> [u8; 32];
    fn encode_data(&self) -> Vec<u8>;
    
    fn struct_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&Self::type_hash());
        hasher.update(&self.encode_data());
        *hasher.finalize().as_bytes()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub requester: String,
    pub nonce: String,
    pub timestamp: u64,
    pub permissions: Vec<String>,
}

impl TypedData for AuthRequest {
    fn type_name() -> &'static str {
        "AuthRequest"
    }
    
    fn type_hash() -> [u8; 32] {
        let type_string = "AuthRequest(string requester,string nonce,uint64 timestamp,string[] permissions)";
        let mut hasher = blake3::Hasher::new();
        hasher.update(TYPE_HASH_CONTEXT);
        hasher.update(type_string.as_bytes());
        *hasher.finalize().as_bytes()
    }
    
    fn encode_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Encode requester
        data.extend_from_slice(&(self.requester.len() as u32).to_be_bytes());
        data.extend_from_slice(self.requester.as_bytes());
        
        // Encode nonce
        data.extend_from_slice(&(self.nonce.len() as u32).to_be_bytes());
        data.extend_from_slice(self.nonce.as_bytes());
        
        // Encode timestamp
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        
        // Encode permissions array
        data.extend_from_slice(&(self.permissions.len() as u32).to_be_bytes());
        for permission in &self.permissions {
            data.extend_from_slice(&(permission.len() as u32).to_be_bytes());
            data.extend_from_slice(permission.as_bytes());
        }
        
        data
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequest {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub nonce: String,
    pub deadline: u64,
}

impl TypedData for TransferRequest {
    fn type_name() -> &'static str {
        "TransferRequest"
    }
    
    fn type_hash() -> [u8; 32] {
        let type_string = "TransferRequest(string from,string to,uint64 amount,string nonce,uint64 deadline)";
        let mut hasher = blake3::Hasher::new();
        hasher.update(TYPE_HASH_CONTEXT);
        hasher.update(type_string.as_bytes());
        *hasher.finalize().as_bytes()
    }
    
    fn encode_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Encode from
        data.extend_from_slice(&(self.from.len() as u32).to_be_bytes());
        data.extend_from_slice(self.from.as_bytes());
        
        // Encode to
        data.extend_from_slice(&(self.to.len() as u32).to_be_bytes());
        data.extend_from_slice(self.to.as_bytes());
        
        // Encode amount
        data.extend_from_slice(&self.amount.to_be_bytes());
        
        // Encode nonce
        data.extend_from_slice(&(self.nonce.len() as u32).to_be_bytes());
        data.extend_from_slice(self.nonce.as_bytes());
        
        // Encode deadline
        data.extend_from_slice(&self.deadline.to_be_bytes());
        
        data
    }
}

pub struct P2PStructuredSigner;

impl P2PStructuredSigner {
    pub fn sign_typed_data<T: TypedData>(
        account: &UnifiedAccount,
        domain: &DomainSeparator,
        data: &T,
    ) -> Result<StructuredSignature<T>, WalletError> {
        let signing_key = account.ed25519_signing_key()
            .ok_or_else(|| WalletError::P2PIdentity("No Ed25519 signing key available".to_string()))?;
        
        let digest = Self::hash_typed_data(domain, data);
        let signature = signing_key.sign(&digest);
        
        Ok(StructuredSignature {
            domain: domain.clone(),
            data: data.clone(),
            signature: hex::encode(signature.to_bytes()),
            type_name: T::type_name().to_string(),
            signature_type: StructuredSignatureType::P2P,
        })
    }
    
    pub fn verify_typed_data<T: TypedData>(
        signature: &StructuredSignature<T>,
        public_key_bytes: &[u8; 32],
    ) -> Result<bool, WalletError> {
        if signature.type_name != T::type_name() {
            return Err(WalletError::P2PIdentity("Type name mismatch".to_string()));
        }
        
        if signature.signature_type != StructuredSignatureType::P2P {
            return Err(WalletError::P2PIdentity("Invalid signature type for P2P verification".to_string()));
        }
        
        let signature_bytes = hex::decode(&signature.signature)
            .map_err(|e| WalletError::P2PIdentity(format!("Invalid signature hex: {}", e)))?;
        
        let ed_signature = Signature::from_bytes(&signature_bytes.try_into()
            .map_err(|_| WalletError::P2PIdentity("Invalid signature length".to_string()))?);
        
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key_bytes)
            .map_err(|e| WalletError::P2PIdentity(format!("Invalid public key: {}", e)))?;
        
        let digest = Self::hash_typed_data(&signature.domain, &signature.data);
        
        Ok(verifying_key.verify(&digest, &ed_signature).is_ok())
    }
    
    fn hash_typed_data<T: TypedData>(domain: &DomainSeparator, data: &T) -> [u8; 32] {
        let domain_hash = domain.hash();
        let struct_hash = data.struct_hash();
        
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"\x19\x01"); // EIP-712 magic bytes
        hasher.update(b"heart-earth-p2p"); // P2P context
        hasher.update(&domain_hash);
        hasher.update(&struct_hash);
        *hasher.finalize().as_bytes()
    }
}

pub struct AccountStructuredSigner;

impl AccountStructuredSigner {
    pub fn sign_typed_data<T: TypedData>(
        account: &UnifiedAccount,
        domain: &DomainSeparator,
        data: &T,
    ) -> Result<StructuredSignature<T>, WalletError> {
        let private_key = account.blockchain_private_key()
            .ok_or_else(|| WalletError::Storage("No blockchain private key available".to_string()))?;
        
        let digest = Self::hash_typed_data(domain, data);
        
        let secp = secp256k1::Secp256k1::signing_only();
        let secret_key = secp256k1::SecretKey::from_byte_array(private_key)
            .map_err(|e| WalletError::Storage(format!("Invalid private key: {}", e)))?;
        
        let secp_message = secp256k1::Message::from_digest(digest);
        let signature = secp.sign_ecdsa(secp_message, &secret_key);
        
        Ok(StructuredSignature {
            domain: domain.clone(),
            data: data.clone(),
            signature: hex::encode(signature.serialize_compact()),
            type_name: T::type_name().to_string(),
            signature_type: StructuredSignatureType::Account,
        })
    }
    
    pub fn verify_typed_data<T: TypedData>(
        signature: &StructuredSignature<T>,
        public_key_bytes: &[u8; 33],
    ) -> Result<bool, WalletError> {
        if signature.type_name != T::type_name() {
            return Err(WalletError::Storage("Type name mismatch".to_string()));
        }
        
        if signature.signature_type != StructuredSignatureType::Account {
            return Err(WalletError::Storage("Invalid signature type for account verification".to_string()));
        }
        
        let signature_bytes = hex::decode(&signature.signature)
            .map_err(|e| WalletError::Storage(format!("Invalid signature hex: {}", e)))?;
        
        let secp = secp256k1::Secp256k1::verification_only();
        let secp_signature = secp256k1::ecdsa::Signature::from_compact(&signature_bytes)
            .map_err(|e| WalletError::Storage(format!("Invalid signature: {}", e)))?;
        
        let public_key = secp256k1::PublicKey::from_slice(public_key_bytes)
            .map_err(|e| WalletError::Storage(format!("Invalid public key: {}", e)))?;
        
        let digest = Self::hash_typed_data(&signature.domain, &signature.data);
        let secp_message = secp256k1::Message::from_digest(digest);
        
        Ok(secp.verify_ecdsa(secp_message, &secp_signature, &public_key).is_ok())
    }
    
    fn hash_typed_data<T: TypedData>(domain: &DomainSeparator, data: &T) -> [u8; 32] {
        let domain_hash = domain.hash();
        let struct_hash = data.struct_hash();
        
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"\x19\x01"); // EIP-712 magic bytes
        hasher.update(b"heart-earth-account"); // Account context
        hasher.update(&domain_hash);
        hasher.update(&struct_hash);
        *hasher.finalize().as_bytes()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StructuredSignatureType {
    P2P,
    Account,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredSignature<T: TypedData> {
    pub domain: DomainSeparator,
    pub data: T,
    pub signature: String,
    pub type_name: String,
    pub signature_type: StructuredSignatureType,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Seed, Wallet, Nonce};

    fn create_test_account() -> UnifiedAccount {
        let seed = Seed::generate(12).unwrap();
        let mut wallet = Wallet::new(seed);
        wallet.generate_account(0, 0).unwrap().clone()
    }

    #[test]
    fn test_domain_separator_hash() {
        let domain1 = DomainSeparator::new(
            "TestApp".to_string(),
            "1".to_string(),
            1,
        );
        
        let domain2 = DomainSeparator::new(
            "TestApp".to_string(),
            "2".to_string(),
            1,
        );
        
        assert_ne!(domain1.hash(), domain2.hash());
    }

    #[test]
    fn test_auth_request_type_hash() {
        let hash1 = AuthRequest::type_hash();
        let hash2 = AuthRequest::type_hash();
        assert_eq!(hash1, hash2); // Should be deterministic
    }

    #[test]
    fn test_auth_request_encoding() {
        let nonce = Nonce::generate().unwrap();
        
        let request1 = AuthRequest {
            requester: "heart123".to_string(),
            nonce: nonce.hex().to_string(),
            timestamp: 1234567890,
            permissions: vec!["read".to_string(), "write".to_string()],
        };
        
        let request2 = AuthRequest {
            requester: "heart123".to_string(),
            nonce: nonce.hex().to_string(),
            timestamp: 1234567890,
            permissions: vec!["read".to_string(), "write".to_string()],
        };
        
        assert_eq!(request1.encode_data(), request2.encode_data());
        assert_eq!(request1.struct_hash(), request2.struct_hash());
    }

    #[test]
    fn test_structured_signing_and_verification() {
        let account = create_test_account();
        let nonce = Nonce::generate().unwrap();
        
        let domain = DomainSeparator::new(
            "TestApp".to_string(),
            "1".to_string(),
            1,
        );
        
        let auth_request = AuthRequest {
            requester: account.peer_id.clone(),
            nonce: nonce.hex().to_string(),
            timestamp: 1234567890,
            permissions: vec!["read".to_string()],
        };
        
        let signature = P2PStructuredSigner::sign_typed_data(&account, &domain, &auth_request).unwrap();
        let public_key = account.ed25519_public_key().unwrap();
        
        let is_valid = P2PStructuredSigner::verify_typed_data(&signature, &public_key).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_transfer_request_signing() {
        let account = create_test_account();
        let nonce = Nonce::generate().unwrap();
        
        let domain = DomainSeparator::new(
            "HeartEarth".to_string(),
            "1".to_string(),
            4361,
        );
        
        let transfer = TransferRequest {
            from: account.blockchain_address.clone(),
            to: "heart456def".to_string(),
            amount: 1000,
            nonce: nonce.hex().to_string(),
            deadline: 9999999999,
        };
        
        let signature = P2PStructuredSigner::sign_typed_data(&account, &domain, &transfer).unwrap();
        let public_key = account.ed25519_public_key().unwrap();
        
        let is_valid = P2PStructuredSigner::verify_typed_data(&signature, &public_key).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_different_domains_produce_different_signatures() {
        let account = create_test_account();
        let nonce = Nonce::generate().unwrap();
        
        let domain1 = DomainSeparator::new("App1".to_string(), "1".to_string(), 1);
        let domain2 = DomainSeparator::new("App2".to_string(), "1".to_string(), 1);
        
        let auth_request = AuthRequest {
            requester: account.peer_id.clone(),
            nonce: nonce.hex().to_string(),
            timestamp: 1234567890,
            permissions: vec!["read".to_string()],
        };
        
        let sig1 = P2PStructuredSigner::sign_typed_data(&account, &domain1, &auth_request).unwrap();
        let sig2 = P2PStructuredSigner::sign_typed_data(&account, &domain2, &auth_request).unwrap();
        
        assert_ne!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_account_structured_signing_and_verification() {
        let account = create_test_account();
        let nonce = Nonce::generate().unwrap();
        
        let domain = DomainSeparator::new(
            "TestApp".to_string(),
            "1".to_string(),
            1,
        );
        
        let transfer = TransferRequest {
            from: account.blockchain_address.clone(),
            to: "heart456def".to_string(),
            amount: 1000,
            nonce: nonce.hex().to_string(),
            deadline: 9999999999,
        };
        
        let signature = AccountStructuredSigner::sign_typed_data(&account, &domain, &transfer).unwrap();
        let public_key = account.blockchain_public_key().unwrap();
        
        let is_valid = AccountStructuredSigner::verify_typed_data(&signature, &public_key).unwrap();
        assert!(is_valid);
        assert_eq!(signature.signature_type, StructuredSignatureType::Account);
    }

    #[test]
    fn test_different_signers_produce_different_signatures() {
        let account = create_test_account();
        let nonce = Nonce::generate().unwrap();
        
        let domain = DomainSeparator::new(
            "TestApp".to_string(),
            "1".to_string(),
            1,
        );
        
        let auth_request = AuthRequest {
            requester: account.blockchain_address.clone(), // Using blockchain address for both
            nonce: nonce.hex().to_string(),
            timestamp: 1234567890,
            permissions: vec!["read".to_string()],
        };
        
        let p2p_sig = P2PStructuredSigner::sign_typed_data(&account, &domain, &auth_request).unwrap();
        let account_sig = AccountStructuredSigner::sign_typed_data(&account, &domain, &auth_request).unwrap();
        
        assert_ne!(p2p_sig.signature, account_sig.signature);
        assert_eq!(p2p_sig.signature_type, StructuredSignatureType::P2P);
        assert_eq!(account_sig.signature_type, StructuredSignatureType::Account);
    }

    #[test]
    fn test_cross_verification_fails() {
        let account = create_test_account();
        let nonce = Nonce::generate().unwrap();
        
        let domain = DomainSeparator::new(
            "TestApp".to_string(),
            "1".to_string(),
            1,
        );
        
        let auth_request = AuthRequest {
            requester: account.blockchain_address.clone(),
            nonce: nonce.hex().to_string(),
            timestamp: 1234567890,
            permissions: vec!["read".to_string()],
        };
        
        let p2p_signature = P2PStructuredSigner::sign_typed_data(&account, &domain, &auth_request).unwrap();
        let account_public_key = account.blockchain_public_key().unwrap();
        
        // Try to verify P2P signature with Account verifier (should fail)
        let result = AccountStructuredSigner::verify_typed_data(&p2p_signature, &account_public_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_types_produce_different_hashes() {
        let nonce = Nonce::generate().unwrap();
        
        let auth_request = AuthRequest {
            requester: "heart123".to_string(),
            nonce: nonce.hex().to_string(),
            timestamp: 1234567890,
            permissions: vec![],
        };
        
        let transfer_request = TransferRequest {
            from: "heart123".to_string(),
            to: "heart456".to_string(),
            amount: 0,
            nonce: nonce.hex().to_string(),
            deadline: 1234567890,
        };
        
        assert_ne!(AuthRequest::type_hash(), TransferRequest::type_hash());
        assert_ne!(auth_request.struct_hash(), transfer_request.struct_hash());
    }
}