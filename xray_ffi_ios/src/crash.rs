use crashreport::panic_handler::CargoPanicMetadata;
use std::backtrace::Backtrace;
use std::os::raw::{c_char, c_void};
use std::panic::PanicHookInfo;
use std::sync::Mutex;

pub(crate) static CRASH_CALLBACK: Mutex<Option<CrashCallback>> = Mutex::new(None);

pub(crate) fn init() {
    let metadata = CargoPanicMetadata {
        repository: option_env!("CARGO_PKG_REPOSITORY").map(|s| s.to_string()),
        version: env!("CARGO_PKG_VERSION").to_string(),
        pkg_name: env!("CARGO_PKG_NAME").to_string(),
        crate_name: env!("CARGO_CRATE_NAME").to_string(),
    };
    crashreport::panic_handler::append_panic_handler(logger, metadata);
}

fn logger(info: &PanicHookInfo<'_>, _metadata: &CargoPanicMetadata) {
    let bt = Backtrace::force_capture();
    let frames = &bt.frames()[..10];
    let message = format!(
        "==== CRASH INFO ====\n{} \n==== BACKTRACE ====\n{:?}",
        info, frames
    );
    let c_msg = std::ffi::CString::new(message).unwrap();
    let ptr = c_msg.as_ptr();
    if let Some(cb) = CRASH_CALLBACK.lock().unwrap().clone() {
        unsafe {
            cb.call(ptr);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn start_xray_crash(
    callback: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    ctx: *mut c_void,
) {
    *CRASH_CALLBACK.lock().unwrap() = Some(CrashCallback(callback, ctx));
    init();
}

#[derive(Clone)]
pub struct CrashCallback(
    Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    *mut c_void,
);

impl CrashCallback {
    unsafe fn call(self, info: *const c_char) {
        if let Some(cb) = self.0 {
            unsafe { cb(info, self.1) };
        }
    }
}
unsafe impl Send for CrashCallback {}
unsafe impl Sync for CrashCallback {}
