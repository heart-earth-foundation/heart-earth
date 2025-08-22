use chrono::Utc;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use ed25519_dalek::{Signature, Signer, Verifier};
use crate::{
    error::WalletError,
    account::UnifiedAccount,
    nonce::Nonce,
};

const P2P_AUTH_CONTEXT: &[u8] = b"heart-earth-auth-p2p";
const ACCOUNT_AUTH_CONTEXT: &[u8] = b"heart-earth-auth-account";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMessage {
    pub domain: String,
    pub address: String,
    pub uri: String,
    pub version: String,
    pub nonce: String,
    pub issued_at: String,
    pub statement: Option<String>,
    pub expiration_time: Option<String>,
    pub not_before: Option<String>,
}

impl AuthMessage {
    pub fn new(
        domain: String,
        address: String,
        uri: String,
        nonce: Nonce,
        statement: Option<String>,
    ) -> Self {
        Self {
            domain,
            address,
            uri,
            version: "1".to_string(),
            nonce: nonce.hex().to_string(),
            issued_at: Utc::now().to_rfc3339(),
            statement,
            expiration_time: None,
            not_before: None,
        }
    }
    
    pub fn with_expiration(mut self, minutes: i64) -> Self {
        let expiration = Utc::now() + chrono::Duration::minutes(minutes);
        self.expiration_time = Some(expiration.to_rfc3339());
        self
    }
    
    pub fn to_message_string(&self) -> String {
        let mut message = format!(
            "{} wants you to sign in with your account:\n{}\n\n",
            self.domain, self.address
        );
        
        if let Some(ref statement) = self.statement {
            message.push_str(&format!("{}\n\n", statement));
        }
        
        message.push_str(&format!("URI: {}\n", self.uri));
        message.push_str(&format!("Version: {}\n", self.version));
        message.push_str(&format!("Nonce: {}\n", self.nonce));
        message.push_str(&format!("Issued At: {}", self.issued_at));
        
        if let Some(ref expiration) = self.expiration_time {
            message.push_str(&format!("\nExpiration Time: {}", expiration));
        }
        
        if let Some(ref not_before) = self.not_before {
            message.push_str(&format!("\nNot Before: {}", not_before));
        }
        
        message
    }
}

pub struct P2PAuthSigner;

impl P2PAuthSigner {
    pub fn sign_message(
        account: &UnifiedAccount,
        message: &AuthMessage,
    ) -> Result<AuthSignature, WalletError> {
        let signing_key = account.ed25519_signing_key()
            .ok_or_else(|| WalletError::P2PIdentity("No Ed25519 signing key available".to_string()))?;
        
        let message_string = message.to_message_string();
        let message_hash = Self::hash_message_with_context(&message_string);
        
        let signature = signing_key.sign(&message_hash);
        
        Ok(AuthSignature {
            signature: hex::encode(signature.to_bytes()),
            message: message.clone(),
            signature_type: SignatureType::P2P,
        })
    }
    
    fn hash_message_with_context(message: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(P2P_AUTH_CONTEXT);
        hasher.update(message.as_bytes());
        hasher.finalize().into()
    }
    
    pub fn verify_signature(
        auth_signature: &AuthSignature,
        public_key_bytes: &[u8; 32],
    ) -> Result<bool, WalletError> {
        if auth_signature.signature_type != SignatureType::P2P {
            return Err(WalletError::P2PIdentity("Invalid signature type for P2P verification".to_string()));
        }
        
        let signature_bytes = hex::decode(&auth_signature.signature)
            .map_err(|e| WalletError::P2PIdentity(format!("Invalid signature hex: {}", e)))?;
        
        let signature = Signature::from_bytes(&signature_bytes.try_into()
            .map_err(|_| WalletError::P2PIdentity("Invalid signature length".to_string()))?);
        
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key_bytes)
            .map_err(|e| WalletError::P2PIdentity(format!("Invalid public key: {}", e)))?;
        
        let message_string = auth_signature.message.to_message_string();
        let message_hash = Self::hash_message_with_context(&message_string);
        
        Ok(verifying_key.verify(&message_hash, &signature).is_ok())
    }
}

pub struct AccountAuthSigner;

impl AccountAuthSigner {
    pub fn sign_message(
        account: &UnifiedAccount,
        message: &AuthMessage,
    ) -> Result<AuthSignature, WalletError> {
        let private_key = account.blockchain_private_key()
            .ok_or_else(|| WalletError::Storage("No blockchain private key available".to_string()))?;
        
        let message_string = message.to_message_string();
        let message_hash = Self::hash_message_with_context(&message_string);
        
        let secp = secp256k1::Secp256k1::signing_only();
        let secret_key = secp256k1::SecretKey::from_byte_array(private_key)
            .map_err(|e| WalletError::Storage(format!("Invalid private key: {}", e)))?;
        
        let secp_message = secp256k1::Message::from_digest(message_hash);
        let signature = secp.sign_ecdsa(secp_message, &secret_key);
        
        Ok(AuthSignature {
            signature: hex::encode(signature.serialize_compact()),
            message: message.clone(),
            signature_type: SignatureType::Account,
        })
    }
    
    fn hash_message_with_context(message: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(ACCOUNT_AUTH_CONTEXT);
        hasher.update(message.as_bytes());
        hasher.finalize().into()
    }
    
    pub fn verify_signature(
        auth_signature: &AuthSignature,
        public_key_bytes: &[u8; 33],
    ) -> Result<bool, WalletError> {
        if auth_signature.signature_type != SignatureType::Account {
            return Err(WalletError::Storage("Invalid signature type for account verification".to_string()));
        }
        
        let signature_bytes = hex::decode(&auth_signature.signature)
            .map_err(|e| WalletError::Storage(format!("Invalid signature hex: {}", e)))?;
        
        let secp = secp256k1::Secp256k1::verification_only();
        let signature = secp256k1::ecdsa::Signature::from_compact(&signature_bytes)
            .map_err(|e| WalletError::Storage(format!("Invalid signature: {}", e)))?;
        
        let public_key = secp256k1::PublicKey::from_slice(public_key_bytes)
            .map_err(|e| WalletError::Storage(format!("Invalid public key: {}", e)))?;
        
        let message_string = auth_signature.message.to_message_string();
        let message_hash = Self::hash_message_with_context(&message_string);
        let secp_message = secp256k1::Message::from_digest(message_hash);
        
        Ok(secp.verify_ecdsa(secp_message, &signature, &public_key).is_ok())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SignatureType {
    P2P,
    Account,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSignature {
    pub signature: String,
    pub message: AuthMessage,
    pub signature_type: SignatureType,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Seed, Wallet};

    fn create_test_account() -> UnifiedAccount {
        let seed = Seed::generate(12).unwrap();
        let mut wallet = Wallet::new(seed);
        wallet.generate_account(0, 0).unwrap().clone()
    }

    #[test]
    fn test_auth_message_creation() {
        let nonce = Nonce::generate().unwrap();
        let message = AuthMessage::new(
            "example.com".to_string(),
            "art1234567890abcdef".to_string(),
            "https://example.com/login".to_string(),
            nonce,
            Some("I accept the Terms of Service".to_string()),
        );
        
        assert_eq!(message.domain, "example.com");
        assert_eq!(message.version, "1");
        assert!(message.statement.is_some());
    }

    #[test]
    fn test_message_string_format() {
        let nonce = Nonce::generate().unwrap();
        let message = AuthMessage::new(
            "example.com".to_string(),
            "art1234567890abcdef".to_string(),
            "https://example.com/login".to_string(),
            nonce,
            Some("I accept the Terms of Service".to_string()),
        );
        
        let message_string = message.to_message_string();
        assert!(message_string.contains("example.com wants you to sign in"));
        assert!(message_string.contains("art1234567890abcdef"));
        assert!(message_string.contains("I accept the Terms of Service"));
    }

    #[test]
    fn test_p2p_signing_and_verification() {
        let account = create_test_account();
        let nonce = Nonce::generate().unwrap();
        
        let message = AuthMessage::new(
            "example.com".to_string(),
            account.peer_id.clone(),
            "https://example.com/login".to_string(),
            nonce,
            None,
        );
        
        let auth_sig = P2PAuthSigner::sign_message(&account, &message).unwrap();
        let public_key = account.ed25519_public_key().unwrap();
        
        let is_valid = P2PAuthSigner::verify_signature(&auth_sig, &public_key).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_account_signing_and_verification() {
        let account = create_test_account();
        let nonce = Nonce::generate().unwrap();
        
        let message = AuthMessage::new(
            "example.com".to_string(),
            account.blockchain_address.clone(),
            "https://example.com/login".to_string(),
            nonce,
            None,
        );
        
        let auth_sig = AccountAuthSigner::sign_message(&account, &message).unwrap();
        let public_key = account.blockchain_public_key().unwrap();
        
        let is_valid = AccountAuthSigner::verify_signature(&auth_sig, &public_key).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_different_contexts_produce_different_signatures() {
        let account = create_test_account();
        let nonce = Nonce::generate().unwrap();
        
        let p2p_message = AuthMessage::new(
            "example.com".to_string(),
            account.peer_id.clone(),
            "https://example.com/login".to_string(),
            nonce.clone(),
            None,
        );
        
        let account_message = AuthMessage::new(
            "example.com".to_string(),
            account.blockchain_address.clone(),
            "https://example.com/login".to_string(),
            nonce,
            None,
        );
        
        let p2p_sig = P2PAuthSigner::sign_message(&account, &p2p_message).unwrap();
        let account_sig = AccountAuthSigner::sign_message(&account, &account_message).unwrap();
        
        assert_ne!(p2p_sig.signature, account_sig.signature);
        assert_eq!(p2p_sig.signature_type, SignatureType::P2P);
        assert_eq!(account_sig.signature_type, SignatureType::Account);
    }
}