use p2p::HeartEarthBehaviour;

mod common;

#[test]
fn test_behaviour_creation() {
    let node = common::create_test_node().unwrap();
    let behaviour = HeartEarthBehaviour::new(*node.peer_id(), node.keypair());
    assert!(behaviour.is_ok());
}

#[test]
fn test_behaviour_components() {
    let node = common::create_test_node().unwrap();
    let behaviour = HeartEarthBehaviour::new(*node.peer_id(), node.keypair()).unwrap();
    
    // Verify all required protocols are initialized
    // These fields are public in the struct
    let _gossipsub = &behaviour.gossipsub;
    let _kademlia = &behaviour.kademlia;
    let _identify = &behaviour.identify;
    let _ping = &behaviour.ping;
}