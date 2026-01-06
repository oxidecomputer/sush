pub mod cli;
pub mod commands;
pub mod permslip;
pub mod repl;

progenitor::generate_api!(
    spec = "../sush.json", // must match `sush_common::OPENAPI_DOCUMENT`
    interface = Positional,
    replace = {
        JobId = sush_common::jobs::JobId,
        JobLimits = sush_common::jobs::JobLimits,
        JobOutputHash = sush_common::jobs::JobOutputHash,
        JobOutputStream = sush_common::jobs::JobOutputStream,
        JobStatus = sush_common::jobs::JobStatus,
        JobsReserved = sush_common::jobs::JobsReserved,
        KeyId = sush_common::certs::KeyId,
        Signature = sush_common::certs::Signature,
        SignedForJobStartRequest = sush_common::jobs::SignedJob,
    },
    timeout = 600,
);
