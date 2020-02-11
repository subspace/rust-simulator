use super::*;
use async_std::sync::{Receiver, Sender};

// ToDo:
// handle exceptions
// I do not have the piece specified by the audit index
// I have multiple pieces, should take the highest quality or return all?
// remove delay

pub async fn run(
    wait_time: u64,
    main_to_sol_rx: Receiver<ProtocolMessage>,
    sol_to_main_tx: Sender<ProtocolMessage>,
    plot: &mut plotter::Plot,
) {
    println!("Solve loop is running...");
    loop {
        match main_to_sol_rx.recv().await.unwrap() {
            ProtocolMessage::BlockChallenge(challenge) => {
                task::sleep(Duration::from_millis(wait_time)).await;
                let solution = plot.solve(challenge, PIECE_COUNT);
                sol_to_main_tx
                    .send(ProtocolMessage::BlockSolution(solution))
                    .await;
            }
            _ => {
                panic!("Solve loop has received a protocol message other than BlockChallenge...");
            }
        }
    }
}
