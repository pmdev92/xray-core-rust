use crate::outbound::quinn_hysteria2::to_io_error;
use quinn::RecvStream;
use quinn_proto::VarInt;
use std::io;
use tokio::io::AsyncReadExt;

pub(crate) async fn decode(recv_stream: &mut RecvStream) -> io::Result<VarInt> {
    let mut first = [0u8; 1];
    recv_stream
        .read_exact(first.as_mut_slice())
        .await
        .map_err(|err| to_io_error(err.to_string()))?;
    let mut first = first[0];
    let tag = first >> 6;
    first &= 0b0011_1111;
    let mut data = vec![first];
    let x = match tag {
        0b00 => u64::from(data[0]),
        0b01 => {
            let mut to_read = [0u8; 1];
            recv_stream
                .read_exact(to_read.as_mut_slice())
                .await
                .map_err(|err| to_io_error(err.to_string()))?;
            data.append(to_read.to_vec().as_mut());
            u64::from(u16::from_be_bytes(data[..2].try_into().unwrap_or([0; 2])))
        }
        0b10 => {
            let mut to_read = [0u8; 3];
            recv_stream
                .read_exact(to_read.as_mut_slice())
                .await
                .map_err(|err| to_io_error(err.to_string()))?;
            data.append(to_read.to_vec().as_mut());
            u64::from(u32::from_be_bytes(data[..4].try_into().unwrap_or([0; 4])))
        }
        0b11 => {
            let mut to_read = [0u8; 7];
            recv_stream
                .read_exact(to_read.as_mut_slice())
                .await
                .map_err(|err| to_io_error(err.to_string()))?;
            data.append(to_read.to_vec().as_mut());
            u64::from(u64::from_be_bytes(data[..8].try_into().unwrap_or([0; 8])))
        }
        _ => unreachable!(),
    };
    VarInt::from_u64(x).map_err(|err| to_io_error(err.to_string()))
}
