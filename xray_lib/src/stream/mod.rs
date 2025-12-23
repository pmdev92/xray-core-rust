use crate::common::net_location::NetLocation;
use crate::core::io::AsyncXrayTcpStream;
use crate::core::stream::StreamSettings;
use crate::stream::exact::ExactWriteStream;
use crate::stream::fragment::FragmentStream;
use std::any::Any;
use std::io;
use std::sync::Arc;

pub mod exact;
pub mod fragment;

pub async fn get_stream(
    context: Arc<crate::core::context::Context>,
    detour: Option<String>,
    stream_settings: Option<StreamSettings>,
    server_net_location: Arc<NetLocation>,
) -> Result<Box<dyn AsyncXrayTcpStream + Send + Sync>, io::Error> {
    match stream_settings {
        None => {}
        Some(stream_settings) => match stream_settings.fragment_settings {
            None => {}
            Some(fragment_settings) => {
                return FragmentStream::new(
                    context,
                    detour,
                    server_net_location.clone(),
                    fragment_settings,
                )
                .await;
            }
        },
    }
    ExactWriteStream::new(context, detour, server_net_location.clone()).await
}
