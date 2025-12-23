use once_cell::sync::Lazy;
use rand::distributions::Alphanumeric;
use rand::rngs::OsRng;
use rand::{Rng, RngCore, thread_rng};

pub(crate) fn get_global_id() -> [u8; 8] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BASE_KEY.as_slice());
    hasher.update(random_string(8).as_bytes());
    let mut output = [0u8; 8];
    let mut output_reader = hasher.finalize_xof();
    output_reader.fill(&mut output);
    output
}

static BASE_KEY: Lazy<[u8; 32]> = Lazy::new(|| {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    return key;
});
fn random_string(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}
