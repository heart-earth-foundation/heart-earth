use std::time::Duration;
use libp2p::{
    Swarm,
    Multiaddr,
    PeerId,
    swarm::SwarmEvent,
    gossipsub::{IdentTopic, Event as GossipsubEvent, Message},
    futures::StreamExt,
};
use tokio::time::timeout;
use p2p::{P2PNode, build_transport, HeartEarthBehaviour, P2PError};
use wallet::{Seed, UnifiedAccount};

const DEV_CHANNEL: &str = "/art/dev/general/v1";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct TestNetwork {
    pub bootstrap: Swarm<HeartEarthBehaviour>,
    pub peers: Vec<Swarm<HeartEarthBehaviour>>,
    pub bootstrap_addr: Option<Multiaddr>,
}

impl TestNetwork {
    pub async fn new(num_peers: usize) -> Result<Self, P2PError> {
        let bootstrap = create_test_swarm().await?;
        let mut peers = Vec::new();
        
        for _ in 0..num_peers {
            peers.push(create_test_swarm().await?);
        }
        
        Ok(Self {
            bootstrap,
            peers,
            bootstrap_addr: None,
        })
    }
    
    pub async fn start_bootstrap(&mut self) -> Result<Multiaddr, P2PError> {
        let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse()
            .map_err(|e| P2PError::Transport(format!("Invalid listen address: {}", e)))?;
        
        self.bootstrap.listen_on(listen_addr.clone())
            .map_err(|e| P2PError::Transport(format!("Failed to listen: {}", e)))?;
        
        let bootstrap_addr = wait_for_listen_addr(&mut self.bootstrap, DEFAULT_TIMEOUT).await?;
        self.bootstrap_addr = Some(bootstrap_addr.clone());
        
        Ok(bootstrap_addr)
    }
    
    pub async fn connect_peer(&mut self, peer_index: usize) -> Result<(), P2PError> {
        if peer_index >= self.peers.len() {
            return Err(P2PError::Transport("Invalid peer index".to_string()));
        }
        
        let bootstrap_addr = self.bootstrap_addr.as_ref()
            .ok_or_else(|| P2PError::Transport("Bootstrap not started".to_string()))?;
        
        self.peers[peer_index].dial(bootstrap_addr.clone())
            .map_err(|e| P2PError::Transport(format!("Failed to dial: {}", e)))?;
        
        // Both swarms need to process events for connection to complete
        wait_for_connection_between_swarms(&mut self.bootstrap, &mut self.peers[peer_index], DEFAULT_TIMEOUT).await?;
        
        Ok(())
    }
    
    pub async fn send_message(&mut self, from: usize, message: &str) -> Result<(), P2PError> {
        let topic = IdentTopic::new(DEV_CHANNEL);
        
        let swarm = if from == usize::MAX {
            &mut self.bootstrap
        } else if from < self.peers.len() {
            &mut self.peers[from]
        } else {
            return Err(P2PError::Transport("Invalid peer index".to_string()));
        };
        
        swarm.behaviour_mut().gossipsub.publish(topic, message.as_bytes())
            .map_err(|e| P2PError::Behaviour(format!("Failed to publish: {}", e)))?;
        
        Ok(())
    }
    
    pub async fn wait_for_message(&mut self, peer: usize, timeout_duration: Duration) -> Result<String, P2PError> {
        let swarm = if peer == usize::MAX {
            &mut self.bootstrap
        } else if peer < self.peers.len() {
            &mut self.peers[peer]
        } else {
            return Err(P2PError::Transport("Invalid peer index".to_string()));
        };
        
        let result = timeout(timeout_duration, async {
            loop {
                let event = swarm.select_next_some().await;
                if let SwarmEvent::Behaviour(behaviour_event) = event {
                    if let p2p::HeartEarthBehaviourEvent::Gossipsub(gossipsub_event) = behaviour_event {
                        if let GossipsubEvent::Message { message, .. } = gossipsub_event {
                            return Ok(String::from_utf8_lossy(&message.data).to_string());
                        }
                    }
                }
            }
        }).await;
        
        match result {
            Ok(content) => content,
            Err(_) => Err(P2PError::Transport("Message timeout".to_string()))
        }
    }
    
    pub async fn subscribe_all_to_topic(&mut self) -> Result<(), P2PError> {
        let topic = IdentTopic::new(DEV_CHANNEL);
        
        self.bootstrap.behaviour_mut().gossipsub.subscribe(&topic)
            .map_err(|e| P2PError::Behaviour(format!("Bootstrap subscribe failed: {}", e)))?;
        
        for peer in &mut self.peers {
            peer.behaviour_mut().gossipsub.subscribe(&topic)
                .map_err(|e| P2PError::Behaviour(format!("Peer subscribe failed: {}", e)))?;
        }
        
        Ok(())
    }
    
    pub fn bootstrap_peer_id(&self) -> &PeerId {
        self.bootstrap.local_peer_id()
    }
    
    pub fn peer_id(&self, index: usize) -> Option<&PeerId> {
        self.peers.get(index).map(|swarm| swarm.local_peer_id())
    }
}

pub async fn create_test_swarm() -> Result<Swarm<HeartEarthBehaviour>, P2PError> {
    let seed = Seed::generate(12)?;
    let account = UnifiedAccount::derive(&seed, 0, 0)?;
    let ed25519_key = account.ed25519_derived_key()
        .ok_or_else(|| P2PError::Identity("No ed25519 key".to_string()))?;
    
    let node = P2PNode::from_wallet_key(ed25519_key)?;
    let transport = build_transport(node.keypair())?;
    let behaviour = HeartEarthBehaviour::new(*node.peer_id(), node.keypair())?;
    
    let swarm = libp2p::SwarmBuilder::with_existing_identity(node.keypair().clone())
        .with_tokio()
        .with_other_transport(|_| transport)
        .expect("Failed to build transport")
        .with_behaviour(|_| behaviour)
        .expect("Failed to build behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    
    Ok(swarm)
}

pub async fn wait_for_listen_addr(
    swarm: &mut Swarm<HeartEarthBehaviour>, 
    timeout_duration: Duration
) -> Result<Multiaddr, P2PError> {
    let result = timeout(timeout_duration, async {
        loop {
            let event = swarm.select_next_some().await;
            if let SwarmEvent::NewListenAddr { address, .. } = event {
                return Ok(address);
            }
        }
    }).await;
    
    match result {
        Ok(addr) => addr,
        Err(_) => Err(P2PError::Transport("Listen address timeout".to_string()))
    }
}

pub async fn wait_for_connection(
    swarm: &mut Swarm<HeartEarthBehaviour>, 
    timeout_duration: Duration
) -> Result<PeerId, P2PError> {
    let result = timeout(timeout_duration, async {
        loop {
            let event = swarm.select_next_some().await;
            if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                return Ok(peer_id);
            }
        }
    }).await;
    
    match result {
        Ok(peer_id) => peer_id,
        Err(_) => Err(P2PError::Transport("Connection timeout".to_string()))
    }
}

pub fn verify_message_authenticity(message: &Message, expected_peer: &PeerId) -> bool {
    message.source.as_ref() == Some(expected_peer)
}

pub async fn wait_for_connection_between_swarms(
    swarm1: &mut Swarm<HeartEarthBehaviour>,
    swarm2: &mut Swarm<HeartEarthBehaviour>,
    timeout_duration: Duration
) -> Result<(), P2PError> {
    let peer1_id = *swarm1.local_peer_id();
    let peer2_id = *swarm2.local_peer_id();
    
    let result = timeout(timeout_duration, async {
        let mut peer1_connected = false;
        let mut peer2_connected = false;
        
        loop {
            tokio::select! {
                event = swarm1.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                        if peer_id == peer2_id {
                            peer1_connected = true;
                        }
                    }
                }
                event = swarm2.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                        if peer_id == peer1_id {
                            peer2_connected = true;
                        }
                    }
                }
            }
            
            if peer1_connected && peer2_connected {
                return Ok::<(), P2PError>(());
            }
        }
    }).await;
    
    match result {
        Ok(_) => Ok(()),
        Err(_) => Err(P2PError::Transport("Bidirectional connection timeout".to_string()))
    }
}