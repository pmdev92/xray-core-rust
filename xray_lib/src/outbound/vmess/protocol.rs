pub const VERSION: u8 = 1;
pub const OPT_CHUNK_STREAM: u8 = 1;
pub const AES_128_GCM_TAG_LEN: usize = 16;
pub const AES_128_GCM_SECURITY_NUM: u8 = 0x03;
pub const CHACHA20POLY1305_SECURITY_NUM: u8 = 0x04;
pub const NONE_SECURITY_NUM: u8 = 0x05;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum VmessInstruction {
    Tcp = 1,
    Udp = 2,
}

#[derive(Debug)]
pub enum VmessSecurity {
    None,
    Aes128Gcm,
    ChaCha20Poly1305,
}

#[derive(PartialEq, Debug)]
pub enum VmessReadState {
    ReadHeaderLength,
    ReadHeader(usize),
    ReadDataLength,
    ReadData(u16),
}

#[derive(PartialEq, Debug)]
pub enum VmessWriteState {
    WriteHeader,
    Done,
}

pub fn generate_iv() -> Vec<u8> {
    let mut salt = [0u8; 16];
    random_buffer(&mut salt);
    salt[0..16].to_vec()
}

pub fn generate_key() -> Vec<u8> {
    let mut salt = [0u8; 16];
    random_buffer(&mut salt);
    salt[0..16].to_vec()
}

pub fn generate_respv() -> u8 {
    let mut salt = [0u8; 1];
    random_buffer(&mut salt);
    salt[0]
}

pub fn random_buffer(iv_or_salt: &mut [u8]) {
    if iv_or_salt.is_empty() {
        return;
    }
    let mut rng = rand::thread_rng();
    loop {
        rand::Rng::fill(&mut rng, iv_or_salt);
        let is_zeros = iv_or_salt.iter().all(|&x| x == 0);
        if !is_zeros {
            break;
        }
    }
}
