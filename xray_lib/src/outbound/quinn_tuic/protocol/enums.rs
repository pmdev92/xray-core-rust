#[derive(Debug, Clone)]
pub(crate) enum UdpRelayMode {
    Native,
    Quic,
}
#[derive(Debug, Clone)]
pub(crate) enum CongestionControl {
    Cubic,
    Bbr,
    NewReno,
}
