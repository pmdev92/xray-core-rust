use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod grpc;
pub mod http2;
pub mod http_hpgrade;
pub mod tcp;
pub mod websocket;
pub mod xhttp;
