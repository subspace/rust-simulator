use super::*;
use async_std::net::UdpSocket;
use async_std::sync::{Arc, Mutex, Receiver, Sender};
use rand::seq::SliceRandom;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/*
  Network Peers
  1. Get potential peers from gateway on startup
  2. Ping each potential peer
  3. Add each peer that responds
  4. Add each unknown peer you receive a message from
  5. Send rpc requests to a single random peer
  6. Send gossip to a random subset of peers
  7. Have a ready list of peers to messages so that selection does not block
*/

/*
  ToDo
    - refactor receive into a method
    - refactor peers into node since both are immutable
    - only send message references over protocol channels to prevent unneeded copying
*/

pub type NodeID = [u8; 32];

#[derive(Clone, Copy, PartialEq)]
pub enum NodeType {
    Gateway,
    Peer,
    Farmer,
}

pub struct Node {
    id: NodeID,
    mode: NodeType,
    addr: SocketAddr,
    socket: UdpSocket,
}

impl Node {
    async fn new(id: [u8; 32], port: u16, ip: Ipv4Addr, mode: NodeType) -> Node {
        let addr = SocketAddr::new(IpAddr::V4(ip), port);
        let socket = UdpSocket::bind(addr).await.unwrap();
        Node {
            id,
            mode,
            addr: socket.local_addr().unwrap(),
            socket,
        }
    }

    async fn send_message(&self, to: SocketAddr, name: NetworkMessageName, data: &[u8]) {
        let message = NetworkMessage {
            to,
            from: self.addr,
            from_id: self.id,
            name,
            data: data.to_vec(),
        };
        self.socket
            .send_to(&message.to_bytes(), &message.to)
            .await
            .unwrap();
        // add to pending requests
        println!("Sent a {:?} message to {}", message.name, message.to);
    }
}

type PeerContactInfo = (NodeID, SocketAddr);

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct PeerList {
    peers: Vec<PeerContactInfo>,
}

impl PeerList {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> PeerList {
        bincode::deserialize(bytes).unwrap()
    }
}

pub struct Peers {
    peers: Arc<Mutex<HashMap<NodeID, SocketAddr>>>,
    max_group_size: usize,
    group: Arc<Mutex<Vec<SocketAddr>>>,
}

impl Peers {
    /// Creates a new empty peers struct
    fn new(max_group_size: usize) -> Peers {
        Peers {
            peers: Arc::new(Mutex::new(HashMap::new())),
            max_group_size,
            group: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// try to add a new peer, resetting contact group afterwards
    async fn try_add(&self, id: NodeID, addr: SocketAddr) {
        let mut group = self.group.lock().await;
        let mut peers = self.peers.lock().await;
        if !peers.contains_key(&id) {
            println!("Adding peer with addr {} to routing table", addr);
            peers.insert(id, addr);

            // get all contacts
            let mut contacts: Vec<SocketAddr> = Vec::new();
            for (_, socket_addr) in peers.iter() {
                contacts.push((*socket_addr).clone());
            }
            let mut group_size = self.max_group_size;
            let contact_size = contacts.len();
            if group_size > contact_size {
                group_size = contact_size;
            }

            let mut rng = thread_rng();
            // // get a subset of contacts
            let random_contacts: Vec<SocketAddr> = contacts
                .choose_multiple(&mut rng, group_size)
                .cloned()
                .collect();

            *group = random_contacts;
        }
    }

    /// Send a ping request to all peers provided from peers request.
    async fn try_ping_all(&self, peer_data: Vec<u8>, node: &Node) {
        let peer_list = PeerList::from_bytes(&peer_data);
        for peer in peer_list.peers.iter() {
            if !self.peers.lock().await.contains_key(&peer.0) {
                node.send_message(peer.1, NetworkMessageName::Ping, &[])
                    .await;
            }
        }
    }

    /// Try to retrieve a peers address by ID
    async fn try_get(&self, id: &NodeID) -> SocketAddr {
        let peers = self.peers.lock().await;
        *peers.get(id).unwrap()
    }

    /// select one known peer at random (for get requests)
    async fn get_random_contact(&self) -> SocketAddr {
        let group = self.group.lock().await;
        let mut rng = thread_rng();
        *group.choose(&mut rng).unwrap()
    }

    /// select one known peer at random, excluding a specific peer (for get retries)
    async fn get_random_contact_excluding(&self, addr: SocketAddr) -> SocketAddr {
        let group = self.group.lock().await;
        let mut rng = thread_rng();
        loop {
            let random_addr = *group.choose(&mut rng).unwrap();
            if random_addr != addr {
                return random_addr;
            }
        }
    }

    /// get all contacts for sending gossip
    async fn get_all_contacts(&self) -> Vec<SocketAddr> {
        self.group.lock().await.to_vec()
    }

    /// get a binary representation of all known peers, excluding the peer making the request
    async fn get_all_except(&self, except: NodeID) -> Vec<u8> {
        let mut peers: Vec<PeerContactInfo> = Vec::new();
        let exception = self.peers.lock().await.remove_entry(&except).unwrap();
        for (node_id, socket_addr) in self.peers.lock().await.iter() {
            peers.push((*node_id, *socket_addr));
        }
        self.try_add(exception.0, exception.1).await;
        let peer_list = PeerList { peers };
        peer_list.to_bytes()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub enum NetworkMessageName {
    Ping,
    Pong,
    PeersRequest,
    PeersResponse,
    BlockRequest,
    BlockResponse,
    BlockProposal,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct NetworkMessage {
    to: SocketAddr,
    from: SocketAddr,
    from_id: NodeID,
    name: NetworkMessageName,
    data: Vec<u8>,
}

impl NetworkMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> NetworkMessage {
        bincode::deserialize(bytes).unwrap()
    }

    pub fn get_id(&self) -> [u8; 32] {
        crypto::digest_sha_256(&self.to_bytes())
    }
}

pub async fn run(
    gateway_addr: SocketAddr,
    id: NodeID,
    port: u16,
    ip: Ipv4Addr,
    mode: NodeType,
    any_to_main_tx: Sender<ProtocolMessage>,
    main_to_net_rx: Receiver<ProtocolMessage>,
) {
    let node = Node::new(id, port, ip, mode).await;
    let peers = Peers::new(4);
    let mut buffer = vec![0u8; 9_000];
    let is_connected = Arc::new(Mutex::new(false));
    let has_peers = Arc::new(Mutex::new(false));
    let is_c = is_connected.clone();
    let has_p = has_peers.clone();

    // listen for incoming UDP messages over the network socket
    let network_listener = async {
        println!("Network listener has started, attempting to connect...");

        if node.mode != NodeType::Gateway {
            // wait for connection
            while !(*is_connected.lock().await) {
                println!("Checking for a message");
                let (len, sender) = node.socket.recv_from(&mut buffer).await.unwrap();
                let message = NetworkMessage::from_bytes(&buffer[0..len]);
                println!("Received a {:?} message from {}", message.name, sender);
                peers.try_add(message.from_id, message.from).await;

                if message.name == NetworkMessageName::Pong {
                    *is_connected.lock().await = true;
                    println!("Connected to gateway!");
                } else {
                    println!(
                        "Did not receive pong as first message! Received: {:?}",
                        message.name
                    );
                }
            }

            // wait for peers
            while !(*has_peers.lock().await) {
                // may have to drop status here to prevent lockout from connect future
                let (len, sender) = node.socket.recv_from(&mut buffer).await.unwrap();
                let message = NetworkMessage::from_bytes(&buffer[0..len]);
                println!("Received a {:?} message from {}", message.name, sender);

                if message.name == NetworkMessageName::PeersResponse {
                    *has_peers.lock().await = true;
                    println!("Received peers from gateway!");
                } else {
                    println!(
                        "Did not receive peers as second message! Received: {:?} ",
                        message.name
                    );
                }
            }
        }

        println!("Network is fully connected and listening for network messages");

        // fully connected, now start message handler loop
        // receive message, deserialize, check peers, and handle
        loop {
            let (len, sender) = node.socket.recv_from(&mut buffer).await.unwrap();
            let message = NetworkMessage::from_bytes(&buffer[0..len]);
            println!("Received a {:?} message from {}", message.name, sender);
            peers.try_add(message.from_id, message.from).await;

            match message.name {
                NetworkMessageName::Ping => {
                    node.send_message(message.from, NetworkMessageName::Pong, &[])
                        .await;
                }
                NetworkMessageName::Pong => {
                    // ToDo: measure latency and add to peers
                }
                NetworkMessageName::PeersRequest => {
                    let contacts = peers.get_all_except(message.from_id).await;
                    node.send_message(message.from, NetworkMessageName::PeersResponse, &contacts)
                        .await;
                }
                NetworkMessageName::PeersResponse => {
                    // try to ping each potential peer, adding them on pong response
                    peers.try_ping_all(message.data, &node).await;
                }
                NetworkMessageName::BlockRequest => {
                    // forward request as protocol message to main
                    let index = utils::bytes_le_to_u32(&message.data[0..4]);
                    any_to_main_tx
                        .send(ProtocolMessage::BlockRequestFrom(message.from, index))
                        .await;
                }
                NetworkMessageName::BlockResponse => {
                    // if empty block response, request from a different peer
                    if message.data.len() == 4 {
                        println!("Peer did not have block at desired index, requesting from a different peer");
                        node.send_message(
                            peers.get_random_contact_excluding(message.from).await,
                            NetworkMessageName::BlockRequest,
                            &message.data[0..4],
                        )
                        .await;
                        continue;
                    }

                    // else forward response as protocol message to main
                    let block = Block::from_bytes(&message.data);
                    any_to_main_tx
                        .send(ProtocolMessage::BlockResponse(block))
                        .await;
                }
                NetworkMessageName::BlockProposal => {
                    // send protocol message to main
                    // main will decide what to do with the block (if duplicate or to rebroadcast)
                    let full_block = FullBlock::from_bytes(&message.data);
                    any_to_main_tx
                        .send(ProtocolMessage::BlockProposal(full_block))
                        .await;
                }
            }
        }
    };

    // listen for new protocol messages over async channel
    let protocol_listener = async {
        println!("Network is listening for protocol messages");
        loop {
            if let Some(message) = main_to_net_rx.recv().await {
                match message {
          ProtocolMessage::BlockRequest(index) => {
            node.send_message(
              peers.get_random_contact().await,
              NetworkMessageName::BlockRequest,
              index.to_le_bytes().as_ref(),
            ).await;
            // wait for timeout, request from a different peer, remove that peer ???
          },
          ProtocolMessage::BlockResponseTo(addr, block_option, block_index) => {

            // return either the block or the index if not found
            let data = match block_option {
              Some(block) => block.to_bytes(),
              None => block_index.to_le_bytes().to_vec(),
            };

            node.send_message(
              addr,
              NetworkMessageName::BlockResponse,
              &data,
            ).await;
          },
          ProtocolMessage::BlockProposal(full_block) => {
            // how to prevent sending back to the peer who sent me the message?
            for addr in peers.get_all_contacts().await.iter() {
              node.send_message(
                *addr,
                NetworkMessageName::BlockProposal,
                &full_block.to_bytes(),
              ).await;
            }
          },
          _ => (
            panic!("Network protocol message listener has received an unknown protocol message")
          ),
        }
            };
        }
    };

    // connect and sync if peer, if gateway do nothing
    let network_startup = async {
        println!("Calling network startup script...");
        match node.mode {
            NodeType::Peer | NodeType::Farmer => {
                // ping gateway every 300 ms until you get a response
                while !(*is_c.lock().await) {
                    println!("Sending ping to gateway on startup");
                    node.send_message(gateway_addr, NetworkMessageName::Ping, &[])
                        .await;
                    task::sleep(Duration::from_millis(300)).await;
                }

                // ask gateway for peers every second until you get a response
                while !(*has_p.lock().await) {
                    println!("Sending peers request to gateway on startup");
                    node.send_message(gateway_addr, NetworkMessageName::PeersRequest, &[])
                        .await;
                    task::sleep(Duration::from_secs(1)).await;
                }
            }
            NodeType::Gateway => {}
        };
    };

    join!(network_listener, protocol_listener, network_startup);
}
