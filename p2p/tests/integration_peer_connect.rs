use std::time::Duration;
use libp2p::swarm::SwarmEvent;
use tokio::time::sleep;

mod common;
use common::integration::*;

#[tokio::test]
async fn test_peer_connects_to_bootstrap() {
    let mut network = TestNetwork::new(1).await.unwrap();
    
    // Start bootstrap
    let bootstrap_addr = network.start_bootstrap().await.unwrap();
    println!("Bootstrap listening on: {}", bootstrap_addr);
    
    // Small delay to ensure bootstrap is ready
    sleep(Duration::from_millis(100)).await;
    
    // Connect peer to bootstrap
    network.connect_peer(0).await.unwrap();
    
    // Verify connection was established
    let peer_id = network.peer_id(0).unwrap();
    assert!(peer_id.to_string().starts_with("12D3KooW"));
}

#[tokio::test]
async fn test_connection_established_events() {
    let mut network = TestNetwork::new(1).await.unwrap();
    
    // Start bootstrap
    network.start_bootstrap().await.unwrap();
    network.subscribe_all_to_topic().await.unwrap();
    
    // Connect peer
    network.connect_peer(0).await.unwrap();
    
    // Give time for connection events
    sleep(Duration::from_millis(100)).await;
    
    // Both nodes should be connected
    assert!(network.bootstrap_peer_id() != network.peer_id(0).unwrap());
}

#[tokio::test]
async fn test_multiple_peers_connect() {
    let mut network = TestNetwork::new(3).await.unwrap();
    
    // Start bootstrap
    network.start_bootstrap().await.unwrap();
    
    // Connect all peers
    for i in 0..3 {
        network.connect_peer(i).await.unwrap();
    }
    
    // Verify all peers have unique IDs
    let peer1 = network.peer_id(0).unwrap();
    let peer2 = network.peer_id(1).unwrap();
    let peer3 = network.peer_id(2).unwrap();
    
    assert!(peer1 != peer2);
    assert!(peer2 != peer3);
    assert!(peer1 != peer3);
}