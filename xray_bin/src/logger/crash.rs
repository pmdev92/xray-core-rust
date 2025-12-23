use std::backtrace::Backtrace;
use std::panic::PanicHookInfo;

use crashreport::panic_handler::CargoPanicMetadata;
use log::error;

pub(crate) fn init() {
    let metadata = CargoPanicMetadata {
        repository: option_env!("CARGO_PKG_REPOSITORY").map(|s| s.to_string()),
        version: env!("CARGO_PKG_VERSION").to_string(),
        pkg_name: env!("CARGO_PKG_NAME").to_string(),
        crate_name: env!("CARGO_CRATE_NAME").to_string(),
    };
    crashreport::panic_handler::append_panic_handler(logger, metadata);
}

pub fn logger(info: &PanicHookInfo<'_>, _metadata: &CargoPanicMetadata) {
    let _bt = Backtrace::force_capture();
    error!("==== CRASH INFO ====\n{}", info);
    // error!("==== BACKTRACE ====\n{:?}", bt);
}
