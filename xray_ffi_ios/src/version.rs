use std::ffi::{c_char, CString};

#[unsafe(no_mangle)]

pub unsafe extern "C" fn xray_version(callback: Option<unsafe extern "C" fn(*const c_char)>) {
    let version = xray_lib::version::VERSION;
    let c_version = CString::new(version).unwrap();
    if let Some(callback) = callback {
        callback(c_version.as_ptr());
    }
}
