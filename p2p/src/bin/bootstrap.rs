use libp2p::{
    gossipsub::IdentTopic,
    swarm::SwarmEvent,
    SwarmBuilder,
    Multiaddr,
    futures::StreamExt,
};
use libp2p_identity::{Keypair, PeerId};
use p2p::{build_transport, HeartEarthBehaviour};
use std::error::Error;

const DEV_CHANNEL: &str = "/art/dev/general/v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let keypair_bytes = std::fs::read("bootstrap_keypair.key")?;
    let keypair = Keypair::from_protobuf_encoding(&keypair_bytes)?;
    let peer_id = PeerId::from(&keypair.public());
    
    let transport = build_transport(&keypair)?;
    let behaviour = HeartEarthBehaviour::new(peer_id, &keypair)?;
    
    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_other_transport(|_| transport)?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|c| c.with_idle_connection_timeout(std::time::Duration::from_secs(60)))
        .build();

    let topic = IdentTopic::new(DEV_CHANNEL);
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    // Use port 4001 for P2P, Railway PORT for HTTP health
    let p2p_port = "4001";
    let http_port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    
    // Listen on TCP for CLI clients
    let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", p2p_port).parse()?;
    swarm.listen_on(tcp_addr)?;
    
    // Listen on WebSocket for web clients
    let ws_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}/ws", p2p_port).parse()?;
    swarm.listen_on(ws_addr)?;
    
    // Add self to Kademlia routing table for proper DHT functionality
    swarm.behaviour_mut().kademlia.set_mode(Some(libp2p::kad::Mode::Server));

    println!("Bootstrap node starting...");
    println!("Peer ID: {}", swarm.local_peer_id());
    println!("Developer channel: {}", DEV_CHANNEL);

    // Start HTTP health server for Railway
    let http_port_clone = http_port.clone();
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
            Ok(Response::new(Full::new(Bytes::from("OK"))))
        }
        
        let bind_addr = format!("0.0.0.0:{}", http_port_clone);
        let listener = TcpListener::bind(&bind_addr).await.unwrap();
        println!("HTTP health server listening on {}", bind_addr);
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                if let Err(e) = http1::Builder::new()
                    .serve_connection(io, service_fn(health_check))
                    .await {
                    eprintln!("Health server error: {}", e);
                }
            });
        }
    });

    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Listening on {address}");
                    if address.to_string().contains("/ws") {
                        println!("Web clients connect: ws://157.245.208.60:4001/ws");
                    }
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
                            match gossip_event {
                                libp2p::gossipsub::Event::Message { 
                                    message, 
                                    message_id,
                                    .. 
                                } => {
                                    if let Some(source) = message.source {
                                        if message.data.len() > 4096 {
                                            println!("Message too large from {}", source);
                                            continue;
                                        }
                                        
                                        if message.topic != topic.hash() {
                                            println!("Invalid topic from {}", source);
                                            continue;
                                        }
                                        
                                        let content = String::from_utf8_lossy(&message.data);
                                        println!("Message from {}: {}", source, content);
                                        println!("Message ID: {}", message_id);
                                    }
                                },
                                libp2p::gossipsub::Event::Subscribed { peer_id, topic } => {
                                    println!("Peer {} subscribed to topic {}", peer_id, topic);
                                },
                                libp2p::gossipsub::Event::Unsubscribed { peer_id, topic } => {
                                    println!("Peer {} unsubscribed from topic {}", peer_id, topic);
                                },
                                _ => {}
                            }
                        }
                        _ => {
                            println!("Other behaviour event: {event:?}");
                        }
                    }
                }
                SwarmEvent::IncomingConnection { connection_id, .. } => {
                    println!("Incoming connection: {connection_id}");
                }
                _ => {
                    println!("Other event: {event:?}");
                }
            }
        }
    }
}