use super::*;
use async_std::sync::{Receiver, Sender};

pub enum ProtocolMessage {
    BlockRequest(u32), // On sync, main forwards block request to Net for tx by P1
    BlockRequestFrom(SocketAddr, u32), // P2 receives at Net and forwards request to main for fetch
    BlockResponseTo(SocketAddr, Option<Block>, u32), // P2 Main forwards response back to Net for tx
    BlockResponse(Block), // P1 receives at Net and forwards response back to Main
    BlockProposal(FullBlock), // Net receives new full block, validates/applies, sends back to net for re-gossip
    BlockChallenge([u8; 32]), // Main sends challenge to solver for evaluation
    BlockSolution(plotter::Solution), // Solver sends solution back to main for application
}

pub async fn run(
    mode: NodeType,
    genesis_piece_hash: [u8; 32],
    quality_threshold: u8,
    binary_public_key: [u8; 32],
    keys: ed25519_dalek::Keypair,
    merkle_proofs: Vec<Vec<u8>>,
    tx_payload: Vec<u8>,
    ledger: &mut Ledger,
    any_to_main_rx: Receiver<ProtocolMessage>,
    main_to_net_tx: Sender<ProtocolMessage>,
    main_to_sol_tx: Sender<ProtocolMessage>,
) {
    let protocol_listener = async {
        println!("Main protocol loop is running...");
        loop {
            if let Some(message) = any_to_main_rx.recv().await {
                match message {
                    ProtocolMessage::BlockRequestFrom(addr, index) => {
                        let block = ledger.get_block_by_index(index);
                        let message = ProtocolMessage::BlockResponseTo(addr, block, index);
                        main_to_net_tx.send(message).await;
                    }
                    ProtocolMessage::BlockResponse(block) => {
                        // validate block
                        if !block.is_valid() {
                            panic!("Received invalid block response while syncing the chain");
                            // later, should request from another peer and black list this peer
                        }

                        match ledger.add_block_by_id(&block) {
                            BlockStatus::Applied => {
                                // may still need to skip the loop before solving, in case any more pending blocks have queued

                                println!("Applied new block received over the network during sync to the ledger");

                                let block_id = block.get_id();

                                // check to see if this block is the parent referenced by any cached blocks
                                if ledger.is_pending_parent(&block_id) {
                                    // fetch the pending full block that references this parent, will call recursive
                                    // let child_id = ledger.get_child_of_pending_parent(&block_id);
                                    let challenge = ledger.apply_pending_block(block_id);
                                    println!("Synced the ledger!");

                                    if mode == NodeType::Farmer || mode == NodeType::Gateway {
                                        main_to_sol_tx
                                            .send(ProtocolMessage::BlockChallenge(challenge))
                                            .await;
                                    }

                                    continue;
                                }

                                // if not then request block at the next index
                                main_to_net_tx
                                    .send(ProtocolMessage::BlockRequest(ledger.height))
                                    .await;
                            }
                            BlockStatus::Pending => {
                                // error in sequencing
                                panic!("Should not be receiving pending blocks as responses during block sync process!");
                            }
                            BlockStatus::Invalid => {
                                panic!("Should not be applying blocks out of order during block sync process!");
                            }
                        }
                    }
                    ProtocolMessage::BlockProposal(full_block) => {
                        let block_id = full_block.block.get_id();

                        // do you already have this block?
                        if ledger.is_block_applied(&block_id) {
                            println!(
                                "Received a block proposal via gossip for known block, ignoring"
                            );
                            continue;
                        }

                        // do you have the parent?
                        if !ledger.is_block_applied(&full_block.block.parent_id) {
                            // cache the block until fully synced
                            // either: still syncing the ledger from startup or received recent blocks out of order
                            println!("Caching a block proposal that is ahead of local ledger with id: {}", hex::encode(full_block.block.get_id()));
                            ledger.cache_pending_block(full_block);
                            continue;
                        }

                        // check quality first
                        if full_block.block.get_quality() < ledger.quality_threshold {
                            println!("Received block proposal with insufficient quality via gossip, ignoring");
                            continue;
                        }

                        // make sure the proof is correct
                        if !full_block.is_valid(
                            PIECE_COUNT,
                            &ledger.merkle_root,
                            &genesis_piece_hash,
                        ) {
                            println!("Received invalid block proposal via gossip, ignoring");
                            continue;
                        }

                        // now we can finally apply the block
                        match ledger.add_block_by_id(&full_block.block) {
              BlockStatus::Applied => {
                println!("Applied new block received over the network via gossip to the ledger");

                // is this the parent of a pending block?
                if ledger.is_pending_parent(&block_id) {
                  let challenge = ledger.apply_pending_block(block_id);

                  if mode == NodeType::Farmer || mode == NodeType::Gateway {
                    main_to_sol_tx.send(ProtocolMessage::BlockChallenge(challenge)).await;
                  }

                  continue;
                }

                // else gossip
                main_to_net_tx.send(ProtocolMessage::BlockProposal(full_block.clone())).await;

                // solve if farming
                if mode == NodeType::Farmer || mode == NodeType::Gateway {
                  main_to_sol_tx.send(ProtocolMessage::BlockChallenge(full_block.block.get_id())).await;
                }
              },
              BlockStatus::Pending => {
                panic!("Logic error, add_block_by_id should not have been called if the parent is unknown...")
              },
              BlockStatus::Invalid => {
                println!("Could not apply block to ledger, illegal extension...");
              },
            }
                    }
                    ProtocolMessage::BlockSolution(solution) => {
                        println!(
                            "Received a solution for challenge: {}",
                            hex::encode(&solution.challenge)
                        );
                        // check solution quality is high enough
                        if solution.quality < quality_threshold {
                            println!("Solution to block challenge does not meet quality threshold, ignoring");
                            continue;
                        }

                        // sign tag and create block
                        let block = Block::new(
                            solution.challenge,
                            solution.tag,
                            binary_public_key,
                            keys.sign(&solution.tag).to_bytes().to_vec(),
                            tx_payload.clone(),
                        );

                        // add block to ledger
                        match ledger.add_block_by_id(&block) {
                            BlockStatus::Applied => {
                                // valid extension to the ledger, gossip to the network
                                println!("Applied new block generated locally to the ledger!");
                                // block.print();

                                let proof = Proof::new(
                                    solution.encoding,
                                    crypto::get_merkle_proof(solution.index, &merkle_proofs),
                                    solution.index,
                                );

                                let solve = main_to_sol_tx
                                    .send(ProtocolMessage::BlockChallenge(block.get_id()));
                                let gossip = main_to_net_tx.send(ProtocolMessage::BlockProposal(
                                    FullBlock { block, proof },
                                ));

                                join!(solve, gossip);
                            }
                            BlockStatus::Invalid => {
                                // illegal extension to the ledger, ignore
                                // may have applied a better block received over the network while the solution was being generated
                                println!("Attempted to add locally generated block to the ledger, but was no longer valid");
                            }
                            BlockStatus::Pending => {
                                // this should not happen, control flow logic error
                                panic!("A block generated locally does not have a known parent...")
                            }
                        }
                    }
                    _ => panic!("Main protocol listener has received an unknown protocol message!"),
                }
            }
        }
    };

    let protocol_startup = async {
        // farm from genesis or sync ledger
        println!("Calling protocol startup");

        match mode {
            NodeType::Gateway => {
                // send genesis challenge to solver
                // this will start an eval loop = solve -> create block -> gossip -> solve ...
                println!(
                    "Starting gateway with genesis challenge: {}",
                    hex::encode(&genesis_piece_hash)
                );
                main_to_sol_tx
                    .send(ProtocolMessage::BlockChallenge(genesis_piece_hash))
                    .await;
            }
            NodeType::Peer | NodeType::Farmer => {
                // start syncing the ledger at the genesis block
                // this will start a sync loop that should complete when fully synced
                // at that point node will simply listen and solve
                task::sleep(Duration::from_secs(3)).await;
                println!("New peer starting ledger sync with gateway");
                main_to_net_tx.send(ProtocolMessage::BlockRequest(0)).await;
            }
        }
    };

    join!(protocol_listener, protocol_startup);
}
