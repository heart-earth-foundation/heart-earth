use std::time::Duration;
use libp2p::{
    gossipsub::IdentTopic,
    swarm::SwarmEvent,
    futures::StreamExt,
};
use tokio::time::sleep;

mod common;
use common::integration::*;

const DEV_CHANNEL: &str = "/art/dev/general/v1";

#[tokio::test]
async fn test_connection_events() {
    // Test that we can detect connection and disconnection events
    let mut bootstrap = create_test_swarm().await.unwrap();
    let mut peer = create_test_swarm().await.unwrap();
    
    let topic = IdentTopic::new(DEV_CHANNEL);
    
    // Setup bootstrap
    bootstrap.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    bootstrap.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
    
    let bootstrap_addr = wait_for_listen_addr(&mut bootstrap, Duration::from_secs(5)).await.unwrap();
    
    // Connect peer
    peer.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    peer.dial(bootstrap_addr).unwrap();
    
    // Wait for connection events like the working code does
    let mut connection_established = false;
    for _ in 0..100 {
        tokio::select! {
            event = bootstrap.select_next_some() => {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("Bootstrap: Connection established with {}", peer_id);
                        connection_established = true;
                    }
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        println!("Bootstrap: Connection closed with {} due to {:?}", peer_id, cause);
                    }
                    SwarmEvent::Behaviour(_) => {
                        // Handle behaviour events
                    }
                    _ => {}
                }
            },
            event = peer.select_next_some() => {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("Peer: Connection established with {}", peer_id);
                        if connection_established {
                            break;
                        }
                    }
                    SwarmEvent::OutgoingConnectionError { error, .. } => {
                        println!("Peer: Outgoing connection error: {:?}", error);
                    }
                    _ => {}
                }
            },
            _ = sleep(Duration::from_millis(50)) => {
                // Keep processing
            }
        }
    }
    
    assert!(connection_established, "Connection should be established");
}

#[tokio::test] 
async fn test_messaging_resilience() {
    // Simple test: messages continue to work even if there are connection errors
    let mut bootstrap = create_test_swarm().await.unwrap();
    let mut peer = create_test_swarm().await.unwrap();
    
    let topic = IdentTopic::new(DEV_CHANNEL);
    
    // Setup like working code
    bootstrap.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    bootstrap.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
    
    let bootstrap_addr = wait_for_listen_addr(&mut bootstrap, Duration::from_secs(5)).await.unwrap();
    
    peer.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    peer.dial(bootstrap_addr).unwrap();
    
    wait_for_connection_between_swarms(&mut bootstrap, &mut peer, Duration::from_secs(10)).await.unwrap();
    
    // Test messaging works like in the working messaging test
    let mut message_received = false;
    for _ in 0..100 {
        tokio::select! {
            event = bootstrap.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(p2p::HeartEarthBehaviourEvent::Gossipsub(
                        libp2p::gossipsub::Event::Message { message, .. }
                    )) => {
                        let content = String::from_utf8_lossy(&message.data);
                        if content.contains("resilience test") {
                            message_received = true;
                            break;
                        }
                    }
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        println!("Connection closed with {} due to {:?}", peer_id, cause);
                    }
                    _ => {}
                }
            },
            _event = peer.select_next_some() => {
                // Process peer events
            },
            _ = sleep(Duration::from_millis(100)) => {
                // Publish like working code handles errors
                if let Err(e) = peer.behaviour_mut().gossipsub.publish(topic.clone(), "resilience test".as_bytes()) {
                    println!("Publish error (expected): {}", e);
                }
            }
        }
    }
    
    assert!(message_received, "Messaging should work despite potential connection issues");
}