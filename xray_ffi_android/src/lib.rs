#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
mod logger;
#[cfg(target_os = "android")]
mod version;

#[cfg(target_os = "android")]
uniffi::include_scaffolding!("xray");

#[cfg(target_os = "android")]
use crate::android::init_asset_path;
#[cfg(target_os = "android")]
use crate::android::shutdown_xray_core;
#[cfg(target_os = "android")]
use crate::android::start_xray_core;
#[cfg(target_os = "android")]
use crate::android::ProtectFd;

#[cfg(target_os = "android")]
use crate::logger::start_xray_logger;
#[cfg(target_os = "android")]
use crate::logger::AndroidLogger;

#[cfg(target_os = "android")]
use crate::version::xray_version;
#[cfg(target_os = "android")]
use crate::version::Version;
