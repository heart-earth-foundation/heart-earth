use libp2p::{
    gossipsub::IdentTopic,
    swarm::SwarmEvent,
    SwarmBuilder,
    Multiaddr,
    futures::StreamExt,
};
use p2p::{P2PNode, build_transport, HeartEarthBehaviour};
use std::error::Error;
use wallet::{Seed, UnifiedAccount};

const DEV_CHANNEL: &str = "/art/dev/general/v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let seed_phrase = std::env::var("BOOTSTRAP_SEED")
        .unwrap_or_else(|_| {
            let seed = Seed::generate(12).expect("Failed to generate seed");
            seed.phrase().to_string()
        });
    
    println!("Bootstrap seed phrase: {}", seed_phrase);
    
    let seed = Seed::from_phrase(&seed_phrase)?;
    let account = UnifiedAccount::derive(&seed, 0, 0)?;
    let ed25519_key = account.ed25519_derived_key()
        .ok_or("No ed25519 key available")?;
    
    let node = P2PNode::from_wallet_key(ed25519_key)?;
    let transport = build_transport(node.keypair())?;
    let behaviour = HeartEarthBehaviour::new(*node.peer_id(), node.keypair())?;
    
    let mut swarm = SwarmBuilder::with_existing_identity(node.keypair().clone())
        .with_tokio()
        .with_other_transport(|_| transport)?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|c| c.with_idle_connection_timeout(std::time::Duration::from_secs(60)))
        .build();

    let topic = IdentTopic::new(DEV_CHANNEL);
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    swarm.behaviour_mut().kademlia.set_mode(Some(libp2p::kad::Mode::Server));

    // Use Railway's TCP application port (defaults to 4001)
    let listen_port = std::env::var("RAILWAY_TCP_APPLICATION_PORT")
        .or_else(|_| std::env::var("PORT"))
        .unwrap_or_else(|_| "4001".to_string());
    
    // Listen on TCP for CLI clients
    let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", listen_port).parse()?;
    swarm.listen_on(tcp_addr)?;
    
    // Listen on WebSocket for web clients  
    let ws_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}/ws", listen_port).parse()?;
    swarm.listen_on(ws_addr)?;
    
    // Start minimal HTTP health server for Railway on a different port
    let health_port = if listen_port == "4001" { "3000" } else { "4001" };
    let health_port_clone = health_port.to_string();
    tokio::spawn(async move {
        use hyper::server::conn::http1;
        use hyper::service::service_fn;
        use hyper::{Request, Response};
        use hyper::body::Bytes;
        use tokio::net::TcpListener;
        use http_body_util::Full;
        use hyper_util::rt::TokioIo;
        use std::convert::Infallible;
        
        async fn health_check(_req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
            Ok(Response::new(Full::new(Bytes::from("P2P Bootstrap Node OK"))))
        }
        
        let bind_addr = format!("0.0.0.0:{}", health_port_clone);
        if let Ok(listener) = TcpListener::bind(&bind_addr).await {
            println!("Health server listening on {}", bind_addr);
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let io = TokioIo::new(stream);
                    tokio::spawn(async move {
                        let _ = http1::Builder::new()
                            .serve_connection(io, service_fn(health_check))
                            .await;
                    });
                }
            }
        }
    });

    println!("Railway Bootstrap node starting...");
    println!("Peer ID: {}", swarm.local_peer_id());
    println!("Port: {}", listen_port);
    println!("Developer channel: {}", DEV_CHANNEL);
    
    // Print connection info for clients
    println!("\nClients can connect via:");
    if let (Ok(domain), Ok(port)) = (
        std::env::var("RAILWAY_TCP_PROXY_DOMAIN"),
        std::env::var("RAILWAY_TCP_PROXY_PORT")
    ) {
        println!("  TCP: /dns4/{}/tcp/{}/p2p/{}", domain, port, swarm.local_peer_id());
    }
    if let Ok(public_domain) = std::env::var("RAILWAY_PUBLIC_DOMAIN") {
        println!("  WebSocket: /dns4/{}/tcp/{}/ws/p2p/{}", public_domain, listen_port, swarm.local_peer_id());
    }

    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Listening on {address}");
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    println!("Peer connected: {peer_id}");
                }
                SwarmEvent::Behaviour(event) => {
                    match event {
                        p2p::HeartEarthBehaviourEvent::Identify(identify_event) => {
                            if let libp2p::identify::Event::Received { peer_id, info, .. } = identify_event {
                                println!("Identified peer: {peer_id}");
                                for addr in info.listen_addrs {
                                    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                                }
                            }
                        }
                        p2p::HeartEarthBehaviourEvent::Gossipsub(gossip_event) => {
                            if let libp2p::gossipsub::Event::Message { message, .. } = gossip_event {
                                let content = String::from_utf8_lossy(&message.data);
                                println!("Message: {}", content);
                            }
                        }
                        _ => {}
                    }
                }
                SwarmEvent::IncomingConnection { connection_id, .. } => {
                    println!("Incoming connection: {connection_id}");
                }
                _ => {}
            }
        }
    }
}