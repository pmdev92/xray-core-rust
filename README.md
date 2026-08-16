# xray-core-rust

Implementation of the xray-core and sing-box cores in the Rust programming language, optimized for operating systems
such as iOS, Android, and more.

## Feature Status Legend

✅ **Implemented** | ❌ **Not Implemented** | 🚧 **Partial/In Progress**

## Config

[🚧 Config Documentation](https://pmdev92.github.io/)

## Build And Run

Clone Project:

```sh
git clone https://github.com/pmdev92/xray-core-rust.git
cd xray-core-rust
```

Run development:

```sh
cargo run run -c CONFIG_PATH
```

Build and run:

```sh
cargo build
./target/debug/xray-core-rust run -c CONFIG_PATH
```

## Inbound Protocols

- ✅ SOCKS5
    - ✅ TCP
    - ✅ UDP
    - ✅ FULL CONE NAT
    - 🚧 AUTH
- ✅ HTTP
- ❌ TUN

## Outbound Protocols

- ✅ Block
- ✅ Direct
- ✅ SOCKS5
    - ✅ TCP
    - ✅ UDP
    - ✅ AUTH (user:password)
    - ✅ Chainable
- ✅ ShadowSocks
    - ✅ All Encryption's
    - ✅ TCP
    - ✅ UDP
    - ✅ UOT V1
    - ✅ UOT V2
    - ✅ Chainable
- ✅ Trojan
    - ✅ TCP
    - ✅ UDP
    - ✅ Chainable
- ✅ VLESS
    - ✅ Flow
    - ✅ TCP
    - ✅ UDP
    - ✅ Chainable
- ✅ VMess
    - ✅ AEAD
    - ✅ TCP
    - ✅ UDP
    - ✅ Chainable
- ✅ Hysteria2
    - ✅ TCP
    - ✅ UDP
    - ✅ Chainable
- ✅ TUIC
    - ✅ TCP
    - ✅ UDP
    - ✅ Chainable

## TCP Transport Protocols

- ✅ TCP
    - ✅ Raw
    - ✅ HTTP
    - ✅ XTLS
- ✅ WebSocket
- ✅ HTTP Upgrade
- ✅ XHTTP
- ✅ HTTP/2
- ✅ GRPC

## TCP Security Protocols

- ✅ TLS
    - ✅ Early Data Supported
    - ✅ XTLS Supported
- 🚧 Reality (Needs Improvement)
    - ✅ Early Data Supported
    - ✅ XTLS Supported

## Router Features

- ✅ Memory Optimized (iOS 50MB Memory Limit)
- ✅ Sniffing
    - ✅ QUIC
    - ✅ TLS
    - ✅ HTTP
- ✅ GeoIP
- ✅ GeoSite
- ❌ DNS

## Roadmap

- Write Tests
- TUN Inbound
- DNS Routing
- Enhanced Statistics

## Credits

- [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [eycorsican/leaf](https://github.com/eycorsican/leaf)
- [Qv2ray/v2ray-rust](https://github.com/Qv2ray/v2ray-rust)
- [cfal/shoes](https://github.com/cfal/shoes)
- [Watfaq/clash-rs](https://github.com/Watfaq/clash-rs)
- [zhangsan946/jets](https://github.com/zhangsan946/jets)
