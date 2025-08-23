use libp2p_identity::{Keypair, PeerId};
use std::error::Error;

#[tokio::test]
async fn test_keypair_persistence() -> Result<(), Box<dyn Error>> {
    // Generate and save keypair
    let keypair1 = Keypair::generate_ed25519();
    let peer_id1 = PeerId::from(&keypair1.public());
    
    let bytes = keypair1.to_protobuf_encoding()?;
    std::fs::write("test_keypair.key", bytes)?;
    
    println!("Generated Peer ID: {}", peer_id1);
    
    // Load keypair and verify same peer ID
    let keypair_bytes = std::fs::read("test_keypair.key")?;
    let keypair2 = Keypair::from_protobuf_encoding(&keypair_bytes)?;
    let peer_id2 = PeerId::from(&keypair2.public());
    
    println!("Loaded Peer ID:    {}", peer_id2);
    
    assert_eq!(peer_id1, peer_id2, "Peer IDs must match after save/load");
    
    // Clean up
    std::fs::remove_file("test_keypair.key")?;
    
    Ok(())
}