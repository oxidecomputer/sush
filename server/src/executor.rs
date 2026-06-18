//! Job execution engine.
//!
//! Executes, monitors, and halts jobs. Driven by the session state machine.

use futures::Stream;
use rumors::Rumors;
use sled_hardware_types::BaseboardId;
use sush_api::JobStartParams;
use sush_common::authn::Identity;
use sush_common::jobs::{JobId, JobOutputStream, JobStartRequest, JobStatus, SignedJob};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use crate::messages::Event;

pub struct Executor {
    events: mpsc::Sender<Event>,
}

impl Executor {
    pub fn new(shutdown: CancellationToken) -> (Self, impl Stream<Item = Event> + Send + 'static) {
        // This is an arbitrary choice; we expect to consume this very rapidly,
        // so should not experience backpressure; if we do, something is wrong.
        let (tx, rx) = mpsc::channel(16);
        (Self { events: tx }, ReceiverStream::new(rx))
    }

    pub fn job_start(&self, _job: &JobStartRequest, _params: &JobStartParams) {
        todo!()
    }

    pub fn job_attach(&self, _job_id: &JobId) {
        todo!()
    }

    pub fn job_status(&self, _job_id: &JobId) {
        todo!()
    }

    pub fn job_stop(&self, _job_id: &JobId) {
        todo!()
    }
}
