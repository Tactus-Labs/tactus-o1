//! Experiment A devnet driver — see `specs/EXPERIMENT_A_DESIGN.md` §8.
//!
//! Talks to a local CKB devnet node over JSON-RPC, builds and signs
//! transactions (molecule encoding hand-rolled in [`molecule`]), deploys the
//! OrderingHead type script and replays the A1 scenario arms on-chain.

pub mod molecule;
pub mod rpc;
pub mod tx;

pub mod lab;

pub mod recovery;

pub mod batch_lab;
pub mod execution_recovery;
pub mod sealed_lab;

pub mod sealed_recovery;
pub mod settlement_inputs;
pub mod settlement_lab;
pub mod settlement_recovery;

pub mod obligation_recovery;

pub mod p2p_lab;
