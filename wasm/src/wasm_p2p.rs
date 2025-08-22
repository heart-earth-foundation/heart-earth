use libp2p_identity::{PeerId, Keypair, ed25519};

pub struct WasmP2P {
    local_peer_id: PeerId,
    _keypair: Keypair,
}

impl WasmP2P {
    pub fn new(ed25519_private_key: &[u8; 32]) -> Result<Self, Box<dyn std::error::Error>> {
        // Create libp2p keypair from ed25519 private key
        let secret_key = ed25519::SecretKey::try_from_bytes(ed25519_private_key.to_vec())?;
        let keypair = ed25519::Keypair::from(secret_key);
        let libp2p_keypair = Keypair::from(keypair);
        let local_peer_id = PeerId::from(&libp2p_keypair.public());

        Ok(Self {
            local_peer_id,
            _keypair: libp2p_keypair,
        })
    }

    pub fn local_peer_id(&self) -> String {
        self.local_peer_id.to_string()
    }
}