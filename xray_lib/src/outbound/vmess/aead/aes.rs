use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

pub trait BlockCipherHelper {
    fn new_with_slice(key: &[u8]) -> Self;
    fn encrypt_with_slice(&self, block: &mut [u8]);
    fn decrypt_with_slice(&self, block: &mut [u8]);
}

impl BlockCipherHelper for Aes128 {
    #[inline]
    fn new_with_slice(key: &[u8]) -> Self {
        let key = GenericArray::from_slice(key);
        Aes128::new(key)
    }

    #[inline]
    fn encrypt_with_slice(&self, block: &mut [u8]) {
        let key = GenericArray::from_mut_slice(block);
        self.encrypt_block(key)
    }

    #[inline]
    fn decrypt_with_slice(&self, block: &mut [u8]) {
        let key = GenericArray::from_mut_slice(block);
        self.decrypt_block(key)
    }
}
