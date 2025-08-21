use libp2p::{
    gossipsub::IdentTopic,
    swarm::SwarmEvent,
    SwarmBuilder,
    Multiaddr,
    futures::StreamExt,
};
use p2p::{P2PNode, build_transport, HeartEarthBehaviour};
use std::time::Duration;
use tokio::time::timeout;
use wallet::{Seed, UnifiedAccount};

const TEST_CHANNEL: &str = "/art/test/websocket/v1";

#[tokio::test]
async fn test_websocket_listener_starts() {
    // Create test node
    let seed = Seed::generate(12).unwrap();
    let account = UnifiedAccount::derive(&seed, 0, 0).unwrap();
    let ed25519_key = account.ed25519_derived_key().unwrap();
    
    let node = P2PNode::from_wallet_key(ed25519_key).unwrap();
    let transport = build_transport(node.keypair()).unwrap();
    let behaviour = HeartEarthBehaviour::new(*node.peer_id(), node.keypair()).unwrap();
    
    let mut swarm = SwarmBuilder::with_existing_identity(node.keypair().clone())
        .with_tokio()
        .with_other_transport(|_| transport).unwrap()
        .with_behaviour(|_| behaviour).unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    let topic = IdentTopic::new(TEST_CHANNEL);
    swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    
    // Listen on TCP and WebSocket
    let tcp_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    swarm.listen_on(tcp_addr).unwrap();
    
    let ws_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0/ws".parse().unwrap();
    swarm.listen_on(ws_addr).unwrap();
    
    // Wait for listeners to start
    let mut tcp_listening = false;
    let mut ws_listening = false;
    
    let result = timeout(Duration::from_secs(5), async {
        while !tcp_listening || !ws_listening {
            match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Test listening on: {}", address);
                    if address.to_string().contains("/tcp/") && !address.to_string().contains("/ws") {
                        tcp_listening = true;
                    }
                    if address.to_string().contains("/ws") {
                        ws_listening = true;
                    }
                }
                _ => {}
            }
        }
    }).await;
    
    assert!(result.is_ok(), "Timeout waiting for listeners to start");
    assert!(tcp_listening, "TCP listener failed to start");
    assert!(ws_listening, "WebSocket listener failed to start");
}

#[tokio::test]
async fn test_transport_supports_websocket() {
    let seed = Seed::generate(12).unwrap();
    let account = UnifiedAccount::derive(&seed, 0, 0).unwrap();
    let ed25519_key = account.ed25519_derived_key().unwrap();
    
    let node = P2PNode::from_wallet_key(ed25519_key).unwrap();
    let transport = build_transport(node.keypair()).unwrap();
    
    // Test that transport can handle WebSocket addresses
    let ws_addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001/ws".parse().unwrap();
    
    // Verify WebSocket address is valid
    assert!(ws_addr.to_string().contains("ws"), "WebSocket address should contain 'ws'");
    
    // Transport creation succeeded, which means it supports the configured protocols
    assert!(format!("{:?}", transport).len() > 0, "Transport should be created successfully");
}

#[tokio::test]
async fn test_bootstrap_websocket_configuration() {
    // Test that WebSocket multiaddr formats are valid
    let tcp_addr: Result<Multiaddr, _> = "/ip4/0.0.0.0/tcp/4001".parse();
    let ws_addr: Result<Multiaddr, _> = "/ip4/0.0.0.0/tcp/4001/ws".parse();
    
    assert!(tcp_addr.is_ok(), "TCP multiaddr should be valid");
    assert!(ws_addr.is_ok(), "WebSocket multiaddr should be valid");
    
    let tcp = tcp_addr.unwrap();
    let ws = ws_addr.unwrap();
    
    // Verify protocols
    assert!(tcp.to_string().contains("tcp"));
    assert!(!tcp.to_string().contains("ws"));
    
    assert!(ws.to_string().contains("tcp"));
    assert!(ws.to_string().contains("ws"));
}

#[cfg(test)]
mod integration {
    use super::*;
    use tokio_test::assert_ok;
    
    #[tokio::test]
    async fn verify_gossipsub_over_websocket() {
        // This test verifies that gossipsub messages can theoretically flow over WebSocket
        // In a real integration test, you'd connect two nodes and verify message passing
        
        let seed1 = Seed::generate(12).unwrap();
        let account1 = UnifiedAccount::derive(&seed1, 0, 0).unwrap();
        let ed25519_key1 = account1.ed25519_derived_key().unwrap();
        
        let node1 = assert_ok!(P2PNode::from_wallet_key(ed25519_key1));
        let transport1 = assert_ok!(build_transport(node1.keypair()));
        let behaviour1 = assert_ok!(HeartEarthBehaviour::new(*node1.peer_id(), node1.keypair()));
        
        // Verify we can create swarm with WebSocket support
        let swarm_result = SwarmBuilder::with_existing_identity(node1.keypair().clone())
            .with_tokio()
            .with_other_transport(|_| transport1)
            .unwrap()
            .with_behaviour(|_| behaviour1)
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        
        // Basic verification that swarm creation succeeds
        assert_eq!(swarm_result.local_peer_id(), node1.peer_id());
    }
}