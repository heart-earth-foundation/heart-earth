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
use wallet::Wallet;

const DEV_CHANNEL: &str = "/art/dev/general/v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Enter mnemonic phrase:");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let mnemonic = input.trim();

    let mut wallet = Wallet::from_mnemonic(mnemonic, None)?;
    let account = wallet.generate_account(0, 0)?;
    
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

    let bootstrap_addr: Multiaddr = "/dns/mainline.proxy.rlwy.net/tcp/49745".parse()?;
    swarm.dial(bootstrap_addr)?;

    println!("Client starting...");
    println!("Peer ID: {}", swarm.local_peer_id());
    println!("Blockchain address: {}", account.blockchain_address);
    println!("Connected to developer channel: {}", DEV_CHANNEL);
    println!("Type messages to send, 'quit' to exit:");

    let mut stdin = io::BufReader::new(io::stdin()).lines();

    loop {
        tokio::select! {
            line = stdin.next_line() => {
                if let Ok(Some(line)) = line {
                    if line == "quit" {
                        break;
                    }
                    let message = format!("[{}]: {}", account.blockchain_address, line);
                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), message.as_bytes()) {
                        println!("Failed to publish message: {e}");
                    }
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(event) => {
                    println!("Event: {event:?}");
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    println!("Connected to {peer_id}");
                }
                _ => {}
            }
        }
    }

    Ok(())
}