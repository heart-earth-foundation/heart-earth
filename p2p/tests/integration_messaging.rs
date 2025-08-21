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
async fn test_simple_messaging() {
    // Create swarms like your bootstrap/client code
    let mut bootstrap = create_test_swarm().await.unwrap();
    let mut peer = create_test_swarm().await.unwrap();
    
    // Bootstrap subscribes and listens (like bootstrap.rs)
    let topic = IdentTopic::new(DEV_CHANNEL);
    bootstrap.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    bootstrap.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
    
    // Wait for listen address
    let bootstrap_addr = wait_for_listen_addr(&mut bootstrap, Duration::from_secs(5)).await.unwrap();
    
    // Peer subscribes and connects (like client.rs)
    peer.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    peer.dial(bootstrap_addr).unwrap();
    
    // Wait for connection
    wait_for_connection_between_swarms(&mut bootstrap, &mut peer, Duration::from_secs(10)).await.unwrap();
    
    // Process events like your working code does with tokio::select!
    let mut message_received = false;
    for _ in 0..100 {
        tokio::select! {
            event = bootstrap.select_next_some() => {
                if let SwarmEvent::Behaviour(p2p::HeartEarthBehaviourEvent::Gossipsub(
                    libp2p::gossipsub::Event::Message { message, .. }
                )) = event {
                    let content = String::from_utf8_lossy(&message.data);
                    if content.contains("test message") {
                        message_received = true;
                        break;
                    }
                }
            },
            event = peer.select_next_some() => {
                // Just process peer events
            },
            _ = sleep(Duration::from_millis(100)) => {
                // Try publishing every 100ms (like your code handles publish errors)
                let _ = peer.behaviour_mut().gossipsub.publish(topic.clone(), "test message".as_bytes());
            }
        }
    }
    
    // Verify message was received
    assert!(message_received, "Message should be received through gossipsub");
}

#[tokio::test]
async fn test_publish_behavior() {
    // Test that publish works like your bootstrap/client code
    let mut swarm = create_test_swarm().await.unwrap();
    let topic = IdentTopic::new(DEV_CHANNEL);
    
    // Subscribe to topic
    swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    
    // Try to publish (may fail with NoPeersSubscribedToTopic like your code)
    let result = swarm.behaviour_mut().gossipsub.publish(topic, "test".as_bytes());
    
    // Your code handles this error by printing it and continuing
    if let Err(e) = result {
        println!("Expected error like your code: {}", e);
        assert!(e.to_string().contains("NoPeersSubscribedToTopic"));
    }
}