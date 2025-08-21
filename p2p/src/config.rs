use libp2p::{Multiaddr, PeerId};
use std::error::Error;

pub struct BootstrapConfig {
    pub peer_id: PeerId,
    pub address: Multiaddr,
}

impl BootstrapConfig {
    pub fn local() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            peer_id: "12D3KooWE21U3xPhRNJtB9e47EvQbuPTmMcgM78DfPMHw3ifKyEF".parse()?,
            address: "/ip4/127.0.0.1/tcp/4001".parse()?,
        })
    }
    
    pub fn railway_wss(domain: &str, peer_id: &str) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            peer_id: peer_id.parse()?,
            address: format!("/dns4/{}/tcp/443/wss/p2p/{}", domain, peer_id).parse()?,
        })
    }
    
    pub fn railway_ws(domain: &str, port: &str, peer_id: &str) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            peer_id: peer_id.parse()?,
            address: format!("/dns4/{}/tcp/{}/ws/p2p/{}", domain, port, peer_id).parse()?,
        })
    }
    
    pub fn from_env() -> Result<Self, Box<dyn Error>> {
        let peer_id_str = std::env::var("BOOTSTRAP_PEER_ID")
            .unwrap_or_else(|_| "12D3KooWE21U3xPhRNJtB9e47EvQbuPTmMcgM78DfPMHw3ifKyEF".to_string());
        
        if let Ok(domain) = std::env::var("BOOTSTRAP_DOMAIN") {
            if let Ok(port) = std::env::var("BOOTSTRAP_PORT") {
                return Self::railway_ws(&domain, &port, &peer_id_str);
            } else {
                return Self::railway_wss(&domain, &peer_id_str);
            }
        }
        
        let address_str = std::env::var("BOOTSTRAP_ADDRESS")
            .unwrap_or_else(|_| "/ip4/127.0.0.1/tcp/4001".to_string());
        
        Ok(Self {
            peer_id: peer_id_str.parse()?,
            address: address_str.parse()?,
        })
    }
}