//! Messages gossiped via rumors.

use std::net::IpAddr;

use thiserror::Error;
use uuid::Uuid;

use sush_common::jobs::{JobId, JobStatus, SessionId, SignedJob};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RequestId(pub Uuid);

#[derive(Clone, Debug)]
pub enum Message {
    Request(RequestId, Request),
    Error(RequestId, Error),
    Event(Event),
}

#[derive(Clone, Debug)]
pub enum Request {
    Session(SessionRequest),
    Job(SessionId, JobRequest),
}

#[derive(Clone, Debug)]
pub enum SessionRequest {
    Start(SessionId),
    Stop(SessionId),
}

#[derive(Clone, Debug)]
pub enum JobRequest {
    Start(SignedJob),
    Stop(JobId),
    Truncate(JobId, usize),
}

#[derive(Clone, Debug)]
pub enum Event {
    Peer(IpAddr),
    Job(SessionId, JobEvent),
}

#[derive(Clone, Debug)]
pub enum JobEvent {
    Status(JobStatus),
}

#[derive(Clone, Debug, Error)]
pub enum Error {}
