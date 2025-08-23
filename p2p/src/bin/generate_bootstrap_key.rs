use libp2p_identity::{Keypair, PeerId};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let keypair = Keypair::generate_ed25519();
    let peer_id = PeerId::from(&keypair.public());
    
    println!("Bootstrap Peer ID: {}", peer_id);
    
    let bytes = keypair.to_protobuf_encoding()?;
    std::fs::write("bootstrap_keypair.key", bytes)?;
    
    println!("Keypair saved to bootstrap_keypair.key");
    
    Ok(())
}