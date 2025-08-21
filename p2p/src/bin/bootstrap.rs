use libp2p::{
    gossipsub::IdentTopic,
    swarm::SwarmEvent,
    SwarmBuilder,
    Multiaddr,
    futures::StreamExt,
};
use p2p::{P2PNode, build_transport, HeartEarthBehaviour};
use std::error::Error;
use tokio::io::{self, AsyncBufReadExt};
use wallet::{Seed, UnifiedAccount};

const DEV_CHANNEL: &str = "/art/dev/general/v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let seed = Seed::generate(12)?;
    let account = UnifiedAccount::derive(&seed, 0, 0)?;
    let ed25519_key = account.ed25519_derived_key()
        .ok_or("No ed25519 key available")?;
    
    let node = P2PNode::from_wallet_key(ed25519_key)?;
    let transport = build_transport(node.keypair())?;
    let behaviour = HeartEarthBehaviour::new(*node.peer_id(), node.keypair())?;
    
    let mut swarm = SwarmBuilder::with_existing_identity(node.keypair().clone())
        .with_tokio()
        .with_other_transport(|_| transport)?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|c| c.with_idle_connection_timeout(std::time::Duration::from_secs(60)))
        .build();

    let topic = IdentTopic::new(DEV_CHANNEL);
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    let port = std::env::var("PORT").unwrap_or_else(|_| "4001".to_string());
    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", port).parse()?;
    swarm.listen_on(listen_addr)?;

    println!("Bootstrap node starting...");
    println!("Peer ID: {}", swarm.local_peer_id());
    println!("Developer channel: {}", DEV_CHANNEL);

    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Listening on {address}");
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    println!("Peer connected: {peer_id}");
                }
                SwarmEvent::Behaviour(event) => {
                    match event {
                        p2p::HeartEarthBehaviourEvent::Identify(identify_event) => {
                            if let libp2p::identify::Event::Received { peer_id, info, .. } = identify_event {
                                println!("Identified peer: {peer_id}");
                                for addr in info.listen_addrs {
                                    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                                }
                            }
                        }
                        _ => {
                            println!("Other behaviour event: {event:?}");
                        }
                    }
                }
                SwarmEvent::IncomingConnection { connection_id, .. } => {
                    println!("Incoming connection: {connection_id}");
                }
                _ => {
                    println!("Other event: {event:?}");
                }
            }
        }
    }

    Ok(())
}