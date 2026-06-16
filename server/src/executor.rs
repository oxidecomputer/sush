//! Job execution engine.
//!
//! Executes, monitors, and halts jobs. Driven by the session state machine.

use sush_api::JobStartParams;
use sush_common::authn::Identity;
use sush_common::jobs::{JobId, JobStatus, SignedJob};

use crate::interactive::SocketSender;
use crate::messages::Error;
use crate::monitor::ExecutionResult;

pub struct Executor {}

impl Executor {
    pub async fn job_start(
        &self,
        _authn: &Identity,
        _job: SignedJob,
        _params: JobStartParams,
    ) -> Result<Option<ExecutionResult>, Error> {
        todo!()
    }

    pub async fn job_start_interactive(
        &self,
        _authn: &Identity,
        _job_id: &JobId,
    ) -> Result<SocketSender, Error> {
        todo!()
    }

    pub async fn job_status(&self, _authn: &Identity, _job_id: &JobId) -> Result<JobStatus, Error> {
        todo!()
    }

    pub async fn job_stop(&self, _authn: &Identity, _job_id: &JobId) -> Result<(), Error> {
        todo!()
    }
}
