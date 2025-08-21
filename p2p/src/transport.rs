use libp2p::{
    core::upgrade,
    noise,
    tcp,
    websocket,
    yamux,
    Transport,
    PeerId,
};
use libp2p_identity::Keypair;
use crate::error::P2PError;

pub fn build_transport(keypair: &Keypair) -> Result<libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>, P2PError> {
    let noise_config = noise::Config::new(keypair)
        .map_err(|e| P2PError::Transport(format!("Noise config error: {:?}", e)))?;

    let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default());
    let ws_transport = websocket::Config::new(tcp::tokio::Transport::new(tcp::Config::default()));
    
    let transport = tcp_transport
        .or_transport(ws_transport)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise_config)
        .multiplex(yamux::Config::default())
        .boxed();

    Ok(transport)
}