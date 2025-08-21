use libp2p_identity::{Keypair, PeerId, ed25519};
use wallet::derivation::Ed25519DerivedKey;
use crate::error::P2PError;

pub struct P2PNode {
    keypair: Keypair,
    peer_id: PeerId,
}

impl P2PNode {
    pub fn from_wallet_key(ed25519_key: &Ed25519DerivedKey) -> Result<Self, P2PError> {
        let secret_key = ed25519::SecretKey::try_from_bytes(ed25519_key.private_key_bytes)
            .map_err(|e| P2PError::Identity(format!("Invalid ed25519 secret key: {:?}", e)))?;
        
        let keypair = ed25519::Keypair::from(secret_key);
        let keypair = Keypair::from(keypair);
        let peer_id = PeerId::from(&keypair.public());
        
        Ok(Self { keypair, peer_id })
    }
    
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }
    
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wallet::{Seed, UnifiedAccount};

    #[test]
    fn test_p2p_node_creation() {
        let seed = Seed::generate(12).unwrap();
        let account = UnifiedAccount::derive(&seed, 0, 0).unwrap();
        let ed25519_key = account.ed25519_derived_key().unwrap();
        
        let node = P2PNode::from_wallet_key(ed25519_key);
        assert!(node.is_ok());
    }

    #[test]
    fn test_peer_id_consistency() {
        let seed = Seed::generate(12).unwrap();
        let account = UnifiedAccount::derive(&seed, 0, 0).unwrap();
        let ed25519_key = account.ed25519_derived_key().unwrap();
        
        let node1 = P2PNode::from_wallet_key(ed25519_key).unwrap();
        let node2 = P2PNode::from_wallet_key(ed25519_key).unwrap();
        
        assert_eq!(node1.peer_id(), node2.peer_id());
    }
}