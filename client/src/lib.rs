pub mod cli;
pub mod commands;
pub mod identity;
pub mod permslip;
pub mod repl;
pub mod session;

progenitor::generate_api!(
    spec = "../sush.json", // must match `sush_common::OPENAPI_DOCUMENT`
    interface = Builder,
    replace = {
        Identity = sush_common::authn::Identity,
        JobId = sush_common::jobs::JobId,
        JobLimits = sush_common::jobs::JobLimits,
        JobOutputHash = sush_common::jobs::JobOutputHash,
        JobOutputStream = sush_common::jobs::JobOutputStream,
        JobStatus = sush_common::jobs::JobStatus,
        KeyId = sush_common::keys::KeyId,
        Signature = sush_common::keys::Signature,
        SignedForJobStartRequest = sush_common::jobs::SignedJob,
    },
    timeout = 600,
);
