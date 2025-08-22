use libp2p::{
    gossipsub::{self, MessageId, MessageAuthenticity, ValidationMode},
    kad,
    identify,
    ping,
    swarm::NetworkBehaviour,
    PeerId,
};
use crate::error::P2PError;

#[derive(NetworkBehaviour)]
pub struct HeartEarthBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
}

impl HeartEarthBehaviour {
    pub fn new(local_peer_id: PeerId, keypair: &libp2p_identity::Keypair) -> Result<Self, P2PError> {
        let message_id_fn = |message: &gossipsub::Message| {
            use sha2::{Sha256, Digest};
            let hash = Sha256::digest(&message.data);
            MessageId::from(hex::encode(hash))
        };

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(std::time::Duration::from_secs(10))
            .validation_mode(ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .mesh_n(2)
            .mesh_n_low(1)
            .mesh_n_high(3)
            .max_transmit_size(4096)
            .max_messages_per_rpc(Some(50))
            .max_ihave_length(1000)
            .build()
            .map_err(|e| P2PError::Behaviour(format!("Gossipsub config error: {}", e)))?;

        let gossipsub = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )
        .map_err(|e| P2PError::Behaviour(format!("Gossipsub creation error: {}", e)))?;

        let kademlia = kad::Behaviour::new(
            local_peer_id,
            kad::store::MemoryStore::new(local_peer_id),
        );

        let identify = identify::Behaviour::new(
            identify::Config::new("heart-earth/1.0.0".to_string(), keypair.public())
        );

        let ping = ping::Behaviour::new(ping::Config::new());

        Ok(Self {
            gossipsub,
            kademlia,
            identify,
            ping,
        })
    }
}