use std::time::Duration;
use libp2p::{
    swarm::SwarmEvent,
    gossipsub::IdentTopic,
};
use tokio::time::timeout;

mod common;
use common::integration::*;

const DEV_CHANNEL: &str = "/art/dev/general/v1";

#[tokio::test]
async fn test_bootstrap_startup() {
    let mut network = TestNetwork::new(0).await.unwrap();
    
    // Start bootstrap and verify it listens
    let bootstrap_addr = network.start_bootstrap().await.unwrap();
    assert!(bootstrap_addr.to_string().contains("127.0.0.1"));
    
    // Subscribe to topic
    let topic = IdentTopic::new(DEV_CHANNEL);
    network.bootstrap.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
}

#[tokio::test]
async fn test_bootstrap_topic_subscription() {
    let mut network = TestNetwork::new(0).await.unwrap();
    network.start_bootstrap().await.unwrap();
    
    let topic = IdentTopic::new(DEV_CHANNEL);
    let result = network.bootstrap.behaviour_mut().gossipsub.subscribe(&topic);
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_bootstrap_peer_id_format() {
    let network = TestNetwork::new(0).await.unwrap();
    let peer_id = network.bootstrap_peer_id();
    let peer_id_str = peer_id.to_string();
    
    assert!(peer_id_str.starts_with("12D3KooW"));
    assert!(peer_id_str.len() > 50);
}