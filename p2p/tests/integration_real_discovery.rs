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
async fn test_real_peer_discovery() {
    // This test verifies the actual peer discovery mechanism
    let mut bootstrap = create_test_swarm().await.unwrap();
    let mut peer = create_test_swarm().await.unwrap();
    
    let topic = IdentTopic::new(DEV_CHANNEL);
    
    // Setup bootstrap
    bootstrap.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    bootstrap.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
    
    let bootstrap_addr = wait_for_listen_addr(&mut bootstrap, Duration::from_secs(5)).await.unwrap();
    
    // Setup peer
    peer.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    peer.dial(bootstrap_addr).unwrap();
    
    // Wait for Identify protocol to exchange info and add peers to Kademlia
    let mut peer_discovered = false;
    let mut bootstrap_discovered = false;
    
    for _ in 0..200 {
        tokio::select! {
            event = bootstrap.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(p2p::HeartEarthBehaviourEvent::Identify(
                        libp2p::identify::Event::Received { peer_id, info, .. }
                    )) => {
                        println!("Bootstrap identified peer: {}", peer_id);
                        // This should happen automatically in the real code
                        for addr in info.listen_addrs {
                            bootstrap.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                        bootstrap_discovered = true;
                    }
                    _ => {}
                }
            },
            event = peer.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(p2p::HeartEarthBehaviourEvent::Identify(
                        libp2p::identify::Event::Received { peer_id, info, .. }
                    )) => {
                        println!("Peer identified bootstrap: {}", peer_id);
                        // This should happen automatically in the real code
                        for addr in info.listen_addrs {
                            peer.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                        peer_discovered = true;
                    }
                    _ => {}
                }
            },
            _ = sleep(Duration::from_millis(50)) => {
                if peer_discovered && bootstrap_discovered {
                    break;
                }
            }
        }
    }
    
    assert!(peer_discovered, "Peer should discover bootstrap through Identify");
    assert!(bootstrap_discovered, "Bootstrap should discover peer through Identify");
    
    // Now test that messaging works after peer discovery
    let mut message_received = false;
    for _ in 0..100 {
        tokio::select! {
            event = bootstrap.select_next_some() => {
                if let SwarmEvent::Behaviour(p2p::HeartEarthBehaviourEvent::Gossipsub(
                    libp2p::gossipsub::Event::Message { message, .. }
                )) = event {
                    let content = String::from_utf8_lossy(&message.data);
                    if content.contains("discovery test") {
                        message_received = true;
                        break;
                    }
                }
            },
            _event = peer.select_next_some() => {},
            _ = sleep(Duration::from_millis(100)) => {
                let _ = peer.behaviour_mut().gossipsub.publish(topic.clone(), "discovery test".as_bytes());
            }
        }
    }
    
    assert!(message_received, "Messages should work after peer discovery");
}