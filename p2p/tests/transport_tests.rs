use p2p::build_transport;

mod common;

#[test]
fn test_transport_creation() {
    let node = common::create_test_node().unwrap();
    let transport = build_transport(node.keypair());
    assert!(transport.is_ok());
}

#[test]
fn test_transport_with_different_keypairs() {
    let node1 = common::create_test_node().unwrap();
    let node2 = common::create_test_node().unwrap();
    
    let transport1 = build_transport(node1.keypair());
    let transport2 = build_transport(node2.keypair());
    
    assert!(transport1.is_ok());
    assert!(transport2.is_ok());
}