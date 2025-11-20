progenitor::generate_api!(
    spec = "../sush.json", // must match `sush_common_lib::OPENAPI_DOCUMENT`
    interface = Positional,
    replace = {
        JobId = sush_common::jobs::JobId,
        JobsReserved = sush_common::jobs::JobsReserved,
        KeyId = sush_common::certs::KeyId,
    },
);
