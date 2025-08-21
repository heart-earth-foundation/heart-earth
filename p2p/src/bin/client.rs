use libp2p::{
    gossipsub::IdentTopic,
    swarm::SwarmEvent,
    SwarmBuilder,
    Multiaddr,
    futures::StreamExt,
};
use p2p::{P2PNode, build_transport, HeartEarthBehaviour};
use std::error::Error;
use tokio::io::{self, AsyncBufReadExt};
use clap::{Parser, Subcommand};
use rpassword;
use zeroize::Zeroizing;
use wallet::{Wallet, WalletStorage, Seed};

const DEV_CHANNEL: &str = "/art/dev/general/v1";

#[derive(Parser)]
#[command(name = "heart-earth-client")]
#[command(about = "Heart Earth P2P Network Client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Create {
        #[arg(short, long, default_value = "default")]
        name: String,
    },
    Login {
        #[arg(short, long, default_value = "default")]
        name: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Create { name } => {
            create_wallet(&name).await?;
        }
        Commands::Login { name } => {
            login_and_connect(&name).await?;
        }
    }
    
    Ok(())
}

async fn create_wallet(name: &str) -> Result<(), Box<dyn Error>> {
    if WalletStorage::wallet_exists(name) {
        eprintln!("Wallet '{}' already exists. Use 'login' command instead.", name);
        return Ok(());
    }
    
    println!("Creating new wallet: {}", name);
    println!();
    
    let password = get_password_with_confirmation()?;
    let seed = Seed::generate(12)?;
    let mnemonic = seed.phrase();
    
    println!("=== IMPORTANT: BACKUP YOUR MNEMONIC PHRASE ===");
    println!();
    println!("Write down these 12 words in order and keep them safe:");
    println!();
    println!("{}", mnemonic);
    println!();
    println!("This is the ONLY time your mnemonic will be displayed!");
    println!("Without it, you cannot recover your wallet.");
    println!();
    print!("Press Enter after you have written down the mnemonic...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    
    WalletStorage::save_encrypted_wallet(name, &mnemonic, &password)?;
    
    println!("Wallet '{}' created successfully!", name);
    println!("Use 'heart-earth-client login --name {}' to connect to the network.", name);
    
    Ok(())
}

async fn login_and_connect(name: &str) -> Result<(), Box<dyn Error>> {
    if !WalletStorage::wallet_exists(name) {
        eprintln!("Wallet '{}' not found. Use 'create' command first.", name);
        return Ok(());
    }
    
    let password = get_password()?;
    let mnemonic = WalletStorage::load_encrypted_wallet(name, &password)?;
    
    let mut wallet = Wallet::from_mnemonic(&mnemonic, None)?;
    let account = wallet.generate_account(0, 0)?;
    
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

    let bootstrap_addr: Multiaddr = "/dns/adequate-bravery-production.up.railway.app/tcp/4001/ws".parse()?;
    swarm.dial(bootstrap_addr)?;

    println!("Client starting...");
    println!("Peer ID: {}", swarm.local_peer_id());
    println!("Blockchain address: {}", account.blockchain_address);
    println!("Connected to developer channel: {}", DEV_CHANNEL);
    println!("Type messages to send, 'quit' to exit:");

    let mut stdin = io::BufReader::new(io::stdin()).lines();

    loop {
        tokio::select! {
            line = stdin.next_line() => {
                if let Ok(Some(line)) = line {
                    if line == "quit" {
                        break;
                    }
                    let message = format!("[{}]: {}", account.blockchain_address, line);
                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), message.as_bytes()) {
                        println!("Failed to publish message: {e}");
                    }
                }
            }
            event = swarm.select_next_some() => match event {
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
                                println!("Received: {}", content);
                            }
                        }
                        _ => {
                            println!("Other event: {event:?}");
                        }
                    }
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    println!("Connected to {peer_id}");
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn get_password() -> Result<Zeroizing<String>, Box<dyn Error>> {
    let password = rpassword::prompt_password("Enter wallet password: ")?;
    Ok(Zeroizing::new(password))
}

fn get_password_with_confirmation() -> Result<Zeroizing<String>, Box<dyn Error>> {
    loop {
        let password1 = rpassword::prompt_password("Enter new password (ASCII only): ")?;
        let password2 = rpassword::prompt_password("Confirm password: ")?;
        
        if password1 == password2 {
            if password1.len() < 8 {
                println!("Password must be at least 8 characters long.");
                continue;
            }
            if !password1.is_ascii() {
                println!("Password must contain only ASCII characters (a-z, A-Z, 0-9, symbols).");
                println!("Unicode characters are not allowed for security reasons.");
                continue;
            }
            return Ok(Zeroizing::new(password1));
        } else {
            println!("Passwords do not match. Please try again.");
        }
    }
}