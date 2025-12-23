use lazy_static::lazy_static;
use std::ops::Deref;
use std::os::raw::c_void;
use std::sync::{Arc, RwLock};
use xray_lib::ContextPlatform;

lazy_static! {
    pub(crate) static ref IOS_PLATFORM_ACCEPTOR: Arc<RwLock<Option<PlatformAcceptorFFI>>> =
        Arc::new(RwLock::new(None));
}

pub struct PlatformAcceptorFFI(unsafe extern "C" fn(*mut c_void) -> bool, *mut c_void);

impl PlatformAcceptorFFI {
    fn can_accept(&self) -> bool {
        unsafe { self.0(self.1) }
    }
}
unsafe impl Send for PlatformAcceptorFFI {}
unsafe impl Sync for PlatformAcceptorFFI {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn start_xray_platform_acceptor(
    callback: unsafe extern "C" fn(*mut c_void) -> bool,
    ctx: *mut c_void,
) {
    *IOS_PLATFORM_ACCEPTOR.write().unwrap() = Some(PlatformAcceptorFFI(callback, ctx));
}

pub(crate) struct IosPlatform {
    callback: Arc<RwLock<Option<PlatformAcceptorFFI>>>,
}
impl IosPlatform {
    pub fn new() -> Box<Self> {
        Box::new(IosPlatform {
            callback: IOS_PLATFORM_ACCEPTOR.clone(),
        })
    }
}
impl ContextPlatform for IosPlatform {
    fn android_protect_fd(&self, _id: u64) {}

    fn can_accept(&self) -> bool {
        let result = self.callback.read();
        match result {
            Ok(callback) => {
                if let Some(c) = callback.deref() {
                    return c.can_accept();
                }
            }
            Err(_) => {}
        }
        true
    }
}
