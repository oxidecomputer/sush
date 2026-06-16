//! Job execution engine.
//!
//! Executes, monitors, and halts jobs. Driven by the session state machine.

use rumors::Rumors;
use sled_hardware_types::BaseboardId;
use sush_api::JobStartParams;
use sush_common::authn::Identity;
use sush_common::jobs::{JobId, JobOutputStream, JobStartRequest, JobStatus, SignedJob};

use crate::interactive::SocketSender;
use crate::messages::{Error, Message};
use crate::monitor::ExecutionResult;

pub struct Executor {
    own_baseboard: BaseboardId,
    rumors: Rumors<Message>,
}

impl Executor {
    pub fn new(own_baseboard: BaseboardId, rumors: Rumors<Message>) -> Self {
        Self {
            own_baseboard,
            rumors,
        }
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
