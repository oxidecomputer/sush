//! Session state manager.
//!
//! Manage sessions and their associated jobs by sending and receiving
//! messages via the gossip protocol.

use crate::executor::Executor;
use crate::messages::Message;

pub struct State {}

pub struct StateManager {
    executor: Executor,
    state: State,
}
