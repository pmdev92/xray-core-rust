use crate::protos::vless_addons::VlessAddons;
use protobuf::Message;
use std::fmt::{Display, Formatter, Write};
use std::io;
use std::sync::Arc;

const XRV: &str = "xtls-rprx-vision";
const XRV_U443: &str = "xtls-rprx-vision-udp443";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VlessFlow {
    None,
    XtlsRprxVision,
    XtlsRprxVisionUdp,
}
impl VlessFlow {
    pub fn from(value: Option<String>) -> Self {
        match value {
            None => {}
            Some(flow) => {
                if flow == XRV {
                    return VlessFlow::XtlsRprxVision;
                }
                if flow == XRV_U443 {
                    return VlessFlow::XtlsRprxVisionUdp;
                }
            }
        }

        return VlessFlow::None;
    }
}

impl Display for VlessFlow {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VlessFlow::None => {
                let _ = f.write_str("NONE");
            }
            VlessFlow::XtlsRprxVision => {
                let _ = f.write_str(XRV);
            }
            VlessFlow::XtlsRprxVisionUdp => {
                let _ = f.write_str(XRV_U443);
            }
        }
        Ok(())
    }
}

pub fn get_vless_addons(flow: VlessFlow) -> Vec<u8> {
    match flow {
        VlessFlow::None => {}
        VlessFlow::XtlsRprxVision => {
            let mut vless_addons = VlessAddons::new();
            vless_addons.Flow = XRV.to_string();

            let result = vless_addons.write_to_bytes();
            match result {
                Ok(mut addon_bytes) => {
                    let length = addon_bytes.len() as u8;
                    let mut addons = vec![length];
                    addons.append(&mut addon_bytes);
                    return addons;
                }
                Err(_) => {}
            }
        }
        VlessFlow::XtlsRprxVisionUdp => {
            let mut vless_addons = VlessAddons::new();
            vless_addons.Flow = XRV_U443.to_string();
            let result = vless_addons.write_to_bytes();
            match result {
                Ok(mut addon_bytes) => {
                    let length = addon_bytes.len() as u8;
                    let mut addons = vec![length];
                    addons.append(&mut addon_bytes);
                    return addons;
                }
                Err(_) => {}
            }
        }
    };
    return vec![0];
}
