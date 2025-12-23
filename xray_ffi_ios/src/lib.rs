#![feature(backtrace_frames)]

pub mod crash;
mod logger;
mod platform;

use crate::platform::IosPlatform;
use std::os::raw::c_char;
use std::{ffi::CStr, thread};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn start_xray_core(id: u32, config: *const c_char) {
    let c_str = unsafe { CStr::from_ptr(config) };
    let config = c_str.to_str().unwrap().to_string();
    thread::spawn(move || {
        let callback = IosPlatform::new();
        xray_lib::start(id, config, Some(callback));
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn shutdown_xray_core(id: u32) {
    let _ = xray_lib::shutdown(id);
}

#[repr(C)]
pub struct StatisticsResult {
    success: bool,
    total_upload: u64,
    total_download: u64,
    duration_upload: u64,
    duration_download: u64,
    duration: u64,
}

#[no_mangle]
pub extern "C" fn get_xray_statistics(id: u32) -> StatisticsResult {
    let response = xray_lib::statistics(id);
    match response {
        Some(result) => StatisticsResult {
            success: true,
            total_upload: result.total_upload,
            total_download: result.total_download,
            duration_upload: result.duration_upload,
            duration_download: result.duration_download,
            duration: result.duration,
        },
        None => StatisticsResult {
            success: false,
            total_upload: 0,
            total_download: 0,
            duration_upload: 0,
            duration_download: 0,
            duration: 0,
        },
    }
}
