use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use futures::{StreamExt, SinkExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{Duration, Instant};
use wallet::message_signing::AuthSignature;
use crate::error::P2PError;

const MAX_MESSAGE_SIZE: usize = 4096;
const RATE_LIMIT_PER_SECOND: u32 = 10;
const MAX_CONNECTIONS: usize = 100;
const NONCE_WINDOW_MINUTES: u64 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserMessage {
    #[serde(rename = "type")]
    pub message_type: String,
    pub topic: String,
    pub data: String,
    pub signature: AuthSignature,
    pub sender: String,
}

#[derive(Debug, Clone)]
pub struct BrowserClient {
    pub peer_id: String,
    pub last_message_time: Instant,
    pub message_count: u32,
    pub connected_at: Instant,
    pub sender: mpsc::UnboundedSender<String>,
}

pub struct BrowserWebSocketServer {
    clients: Arc<RwLock<HashMap<String, BrowserClient>>>,
    used_nonces: Arc<RwLock<HashMap<String, Instant>>>,
    gossipsub_sender: mpsc::UnboundedSender<(String, String)>,
    gossipsub_receiver: Arc<Mutex<mpsc::UnboundedReceiver<(String, String, String)>>>,
}

impl BrowserWebSocketServer {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<(String, String)>, mpsc::UnboundedSender<(String, String, String)>) {
        let (gossipsub_tx, gossipsub_rx) = mpsc::unbounded_channel();
        let (browser_tx, browser_rx) = mpsc::unbounded_channel();
        
        let server = Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            used_nonces: Arc::new(RwLock::new(HashMap::new())),
            gossipsub_sender: gossipsub_tx,
            gossipsub_receiver: Arc::new(Mutex::new(browser_rx)),
        };
        
        (server, gossipsub_rx, browser_tx)
    }

    pub async fn start(&self, bind_addr: &str) -> Result<(), P2PError> {
        let listener = TcpListener::bind(bind_addr).await
            .map_err(|e| P2PError::Transport(format!("Failed to bind WebSocket server: {}", e)))?;
        
        println!("Browser WebSocket server listening on {}", bind_addr);

        let clients = Arc::clone(&self.clients);
        let used_nonces = Arc::clone(&self.used_nonces);
        let gossipsub_sender = self.gossipsub_sender.clone();
        let gossipsub_receiver = Arc::clone(&self.gossipsub_receiver);

        tokio::spawn(async move {
            Self::cleanup_expired_nonces(used_nonces).await;
        });

        tokio::spawn(async move {
            Self::broadcast_gossipsub_messages(clients, gossipsub_receiver).await;
        });

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let clients = Arc::clone(&self.clients);
                    let used_nonces = Arc::clone(&self.used_nonces);
                    let gossipsub_sender = gossipsub_sender.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, clients, used_nonces, gossipsub_sender).await {
                            println!("Browser WebSocket connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    println!("Failed to accept browser connection: {}", e);
                }
            }
        }
    }

    async fn handle_connection(
        stream: TcpStream,
        clients: Arc<RwLock<HashMap<String, BrowserClient>>>,
        used_nonces: Arc<RwLock<HashMap<String, Instant>>>,
        gossipsub_sender: mpsc::UnboundedSender<(String, String)>,
    ) -> Result<(), P2PError> {
        let websocket = accept_async(stream).await
            .map_err(|e| P2PError::Transport(format!("WebSocket handshake failed: {}", e)))?;

        let (ws_sender, mut ws_receiver) = websocket.split();
        let (client_tx, mut client_rx) = mpsc::unbounded_channel::<String>();
        let mut client_peer_id: Option<String> = None;

        // Spawn task to handle outgoing messages to this client
        let ws_sender = Arc::new(Mutex::new(ws_sender));
        let ws_sender_clone = Arc::clone(&ws_sender);
        tokio::spawn(async move {
            while let Some(message) = client_rx.recv().await {
                let mut sender = ws_sender_clone.lock().await;
                if let Err(_) = sender.send(Message::Text(message.into())).await {
                    break;
                }
            }
        });

        while let Some(message) = ws_receiver.next().await {
            match message {
                Ok(Message::Text(text)) => {
                    if text.len() > MAX_MESSAGE_SIZE {
                        let mut sender = ws_sender.lock().await;
                        let _ = sender.send(Message::Close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Size,
                            reason: "Message too large".into(),
                        }))).await;
                        break;
                    }

                    match Self::process_message(&text, &clients, &used_nonces, &gossipsub_sender).await {
                        Ok(peer_id) => {
                            if client_peer_id.is_none() {
                                client_peer_id = Some(peer_id.clone());
                                Self::add_client(&clients, peer_id, client_tx.clone()).await;
                            }
                        }
                        Err(e) => {
                            println!("Message processing error: {}", e);
                            let error_response = serde_json::json!({
                                "type": "error",
                                "message": "Invalid message"
                            });
                            let _ = client_tx.send(error_response.to_string());
                        }
                    }
                }
                Ok(Message::Close(_)) => {
                    break;
                }
                Err(e) => {
                    println!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }

        if let Some(peer_id) = client_peer_id {
            Self::remove_client(&clients, &peer_id).await;
        }

        Ok(())
    }

    async fn process_message(
        text: &str,
        clients: &Arc<RwLock<HashMap<String, BrowserClient>>>,
        used_nonces: &Arc<RwLock<HashMap<String, Instant>>>,
        gossipsub_sender: &mpsc::UnboundedSender<(String, String)>,
    ) -> Result<String, P2PError> {
        let browser_message: BrowserMessage = serde_json::from_str(text)
            .map_err(|e| P2PError::Message(format!("Invalid JSON: {}", e)))?;

        if browser_message.message_type != "publish" {
            return Err(P2PError::Message("Unsupported message type".to_string()));
        }

        Self::verify_message_signature(&browser_message).await?;
        Self::check_nonce_replay(&browser_message, used_nonces).await?;
        Self::check_rate_limit(&browser_message.sender, clients).await?;

        gossipsub_sender.send((browser_message.topic, browser_message.data))
            .map_err(|e| P2PError::Message(format!("Failed to send to gossipsub: {}", e)))?;

        Ok(browser_message.sender)
    }

    async fn verify_message_signature(message: &BrowserMessage) -> Result<(), P2PError> {
        use wallet::message_signing::P2PAuthSigner;
        use libp2p_identity::PeerId;
        use std::str::FromStr;
        
        let peer_id = PeerId::from_str(&message.sender)
            .map_err(|e| P2PError::Message(format!("Invalid peer ID: {}", e)))?;
        
        let public_key_bytes = peer_id.to_bytes();
        if public_key_bytes.len() < 32 {
            return Err(P2PError::Message("Invalid peer ID length".to_string()));
        }
        
        let ed25519_key_slice = &public_key_bytes[public_key_bytes.len() - 32..];
        let mut ed25519_key = [0u8; 32];
        ed25519_key.copy_from_slice(ed25519_key_slice);
        
        let is_valid = P2PAuthSigner::verify_signature(&message.signature, &ed25519_key)
            .unwrap_or(false);
        
        if !is_valid {
            return Err(P2PError::Message("Invalid signature".to_string()));
        }
        
        Ok(())
    }

    async fn check_nonce_replay(
        message: &BrowserMessage,
        used_nonces: &Arc<RwLock<HashMap<String, Instant>>>,
    ) -> Result<(), P2PError> {
        let nonce = &message.signature.message.nonce;
        let mut nonces = used_nonces.write().await;
        
        if nonces.contains_key(nonce) {
            return Err(P2PError::Message("Nonce replay detected".to_string()));
        }
        
        nonces.insert(nonce.clone(), Instant::now());
        Ok(())
    }

    async fn check_rate_limit(
        peer_id: &str,
        clients: &Arc<RwLock<HashMap<String, BrowserClient>>>,
    ) -> Result<(), P2PError> {
        let mut clients = clients.write().await;
        
        if let Some(client) = clients.get_mut(peer_id) {
            let now = Instant::now();
            let time_since_last = now.duration_since(client.last_message_time);
            
            if time_since_last >= Duration::from_secs(1) {
                client.message_count = 1;
                client.last_message_time = now;
            } else {
                client.message_count += 1;
                if client.message_count > RATE_LIMIT_PER_SECOND {
                    return Err(P2PError::Message("Rate limit exceeded".to_string()));
                }
            }
        }
        
        Ok(())
    }

    async fn add_client(
        clients: &Arc<RwLock<HashMap<String, BrowserClient>>>,
        peer_id: String,
        sender: mpsc::UnboundedSender<String>,
    ) {
        let mut clients = clients.write().await;
        
        if clients.len() >= MAX_CONNECTIONS {
            return;
        }
        
        let peer_id_clone = peer_id.clone();
        clients.insert(peer_id.clone(), BrowserClient {
            peer_id,
            last_message_time: Instant::now(),
            message_count: 0,
            connected_at: Instant::now(),
            sender,
        });
        
        println!("Browser client connected: {} (total: {})", peer_id_clone, clients.len());
    }

    async fn remove_client(
        clients: &Arc<RwLock<HashMap<String, BrowserClient>>>,
        peer_id: &str,
    ) {
        let mut clients = clients.write().await;
        clients.remove(peer_id);
        println!("Browser client disconnected: {} (total: {})", peer_id, clients.len());
    }

    async fn cleanup_expired_nonces(used_nonces: Arc<RwLock<HashMap<String, Instant>>>) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            let mut nonces = used_nonces.write().await;
            let cutoff = Instant::now() - Duration::from_secs(NONCE_WINDOW_MINUTES * 60);
            nonces.retain(|_, timestamp| *timestamp > cutoff);
        }
    }

    async fn broadcast_gossipsub_messages(
        clients: Arc<RwLock<HashMap<String, BrowserClient>>>,
        gossipsub_receiver: Arc<Mutex<mpsc::UnboundedReceiver<(String, String, String)>>>,
    ) {
        let mut receiver = gossipsub_receiver.lock().await;
        
        while let Some((topic, data, sender)) = receiver.recv().await {
            let clients = clients.read().await;
            let message = serde_json::json!({
                "type": "message",
                "topic": topic,
                "data": data,
                "sender": sender,
                "timestamp": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
            });
            
            for client in clients.values() {
                let _ = client.sender.send(message.to_string());
            }
            println!("Broadcasted to {} browsers: {}", clients.len(), message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wallet::{Seed, UnifiedAccount, message_signing::{AuthMessage, P2PAuthSigner}, nonce::Nonce};

    #[tokio::test]
    async fn test_browser_websocket_server_creation() {
        let (server, _gossipsub_rx, _browser_tx) = BrowserWebSocketServer::new();
        assert_eq!(server.clients.read().await.len(), 0);
    }

    #[test]
    fn test_message_size_limit() {
        assert!(MAX_MESSAGE_SIZE == 4096);
        assert!(RATE_LIMIT_PER_SECOND == 10);
        assert!(MAX_CONNECTIONS == 100);
    }

    #[tokio::test]
    async fn test_message_authentication() {
        let seed = Seed::generate(12).unwrap();
        let account = UnifiedAccount::derive(&seed, 0, 0).unwrap();
        
        let nonce = Nonce::generate().unwrap();
        let auth_message = AuthMessage::new(
            "test.local".to_string(),
            account.blockchain_address.clone(),
            "https://test.local".to_string(),
            nonce,
            Some("Test message".to_string()),
        );
        
        let signature = P2PAuthSigner::sign_message(&account, &auth_message).unwrap();
        
        let browser_message = BrowserMessage {
            message_type: "publish".to_string(),
            topic: "/art/dev/general/v1".to_string(),
            data: "test data".to_string(),
            signature,
            sender: account.peer_id.clone(),
        };
        
        let result = BrowserWebSocketServer::verify_message_signature(&browser_message).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_nonce_replay_protection() {
        let used_nonces = Arc::new(RwLock::new(HashMap::new()));
        
        let seed = Seed::generate(12).unwrap();
        let account = UnifiedAccount::derive(&seed, 0, 0).unwrap();
        
        let nonce = Nonce::generate().unwrap();
        let auth_message = AuthMessage::new(
            "test.local".to_string(),
            account.blockchain_address.clone(),
            "https://test.local".to_string(),
            nonce,
            Some("Test message".to_string()),
        );
        
        let signature = P2PAuthSigner::sign_message(&account, &auth_message).unwrap();
        
        let browser_message = BrowserMessage {
            message_type: "publish".to_string(),
            topic: "/art/dev/general/v1".to_string(),
            data: "test data".to_string(),
            signature,
            sender: account.peer_id.clone(),
        };
        
        // First use should succeed
        let result1 = BrowserWebSocketServer::check_nonce_replay(&browser_message, &used_nonces).await;
        assert!(result1.is_ok());
        
        // Second use should fail (replay)
        let result2 = BrowserWebSocketServer::check_nonce_replay(&browser_message, &used_nonces).await;
        assert!(result2.is_err());
        assert!(result2.unwrap_err().to_string().contains("replay"));
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let clients = Arc::new(RwLock::new(HashMap::new()));
        let peer_id = "test_peer_12345";
        
        // Add a client first
        {
            let mut clients_write = clients.write().await;
            let (tx, _rx) = mpsc::unbounded_channel::<String>();
            clients_write.insert(peer_id.to_string(), BrowserClient {
                peer_id: peer_id.to_string(),
                last_message_time: Instant::now(),
                message_count: 0,
                connected_at: Instant::now(),
                sender: tx,
            });
        }
        
        // Simulate multiple rapid messages
        for i in 0..15_u32 {
            let result = BrowserWebSocketServer::check_rate_limit(peer_id, &clients).await;
            if i < RATE_LIMIT_PER_SECOND {
                assert!(result.is_ok(), "Message {} should succeed", i);
            } else {
                assert!(result.is_err(), "Message {} should be rate limited", i);
                assert!(result.unwrap_err().to_string().contains("Rate limit"));
                break;
            }
        }
    }
}