use libp2p_identity::{PeerId, Keypair, secp256k1, ed25519};
use crate::{error::WalletError, derivation::Ed25519DerivedKey};

pub struct P2PIdentity {
    keypair: Keypair,
    peer_id: PeerId,
}

impl P2PIdentity {
    pub fn from_private_key(private_key: &[u8; 32]) -> Result<Self, WalletError> {
        let secret_key = secp256k1::SecretKey::try_from_bytes(private_key.to_vec())
            .map_err(|e| WalletError::P2PIdentity(format!("Invalid secret key: {:?}", e)))?;
        
        let keypair = secp256k1::Keypair::from(secret_key);
        let keypair = Keypair::from(keypair);
        let peer_id = PeerId::from(&keypair.public());
        
        Ok(Self { keypair, peer_id })
    }
    
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
    
    pub fn peer_id_string(&self) -> String {
        self.peer_id.to_string()
    }
    
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.keypair.public().encode_protobuf()
    }
    
    pub fn from_ed25519_key(ed25519_key: &Ed25519DerivedKey) -> Result<Self, WalletError> {
        let secret_key = ed25519::SecretKey::try_from_bytes(ed25519_key.private_key_bytes)
            .map_err(|e| WalletError::P2PIdentity(format!("Invalid ed25519 secret key: {:?}", e)))?;
        
        let keypair = ed25519::Keypair::from(secret_key);
        let keypair = Keypair::from(keypair);
        let peer_id = PeerId::from(&keypair.public());
        
        Ok(Self { keypair, peer_id })
    }
    
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }
}