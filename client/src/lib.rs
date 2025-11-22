pub mod permslip;
pub use permslip::PermslipSigner;

progenitor::generate_api!(
    spec = "../sush.json", // must match `sush_common::OPENAPI_DOCUMENT`
    interface = Positional,
    replace = {
        JobId = sush_common::jobs::JobId,
        JobsReserved = sush_common::jobs::JobsReserved,
        KeyId = sush_common::certs::KeyId,
        Signature = sush_common::certs::Signature,
        SignedForJobStartRequest = sush_common::jobs::SignedJob,
    },
);
