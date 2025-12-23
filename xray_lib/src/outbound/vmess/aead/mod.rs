use std::slice::from_raw_parts_mut;

use ::aes::Aes128;
use aes_gcm::Aes128Gcm;
use bytes::{BufMut, BytesMut};

use aes::BlockCipherHelper;

use crate::outbound::vmess::aead::helper::AeadCipherHelper;
use crate::outbound::vmess::kdf::{
    vmess_kdf_1_one_shot, vmess_kdf_3_one_shot, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV, KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
};
use crate::outbound::vmess::protocol::{random_buffer, AES_128_GCM_TAG_LEN};

mod aes;
mod helper;

fn create_auth_id(cmd_key: &[u8], time: &[u8]) -> BytesMut {
    let mut buf = BytesMut::new();
    buf.put_slice(time);
    let mut random_bytes = [0u8; 4];
    random_buffer(&mut random_bytes);
    buf.put_slice(&random_bytes);
    let zero = crc32fast::hash(&*buf);
    buf.put_u32(zero);
    let key = vmess_kdf_1_one_shot(cmd_key, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY);
    let block = Aes128::new_with_slice(&key[0..16]);
    block.encrypt_with_slice(&mut buf);
    buf
}

pub fn seal_vmess_aead_header(cmd_key: &[u8], data: &[u8]) -> BytesMut {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_be_bytes();

    let mut generated_auth_id = create_auth_id(cmd_key, &time);
    let id_len = generated_auth_id.len();
    let mut connection_nonce = [0u8; 8];
    random_buffer(&mut connection_nonce);

    // reserve (header_length + nonce + data + 2*tag) bytes
    // total_len = 16 +
    generated_auth_id.reserve(2 + connection_nonce.len() + data.len() + 2 * AES_128_GCM_TAG_LEN);
    {
        let payload_header_length_aeadkey = vmess_kdf_3_one_shot(
            cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
            &*generated_auth_id,
            &connection_nonce,
        );
        let payload_header_length_aead_nonce = vmess_kdf_3_one_shot(
            cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
            &generated_auth_id,
            &connection_nonce,
        );
        let nonce = &payload_header_length_aead_nonce[..12];
        let cipher = Aes128Gcm::new_with_slice(&payload_header_length_aeadkey[0..16]);
        let mbuf = &mut generated_auth_id.chunk_mut()[..2 + AES_128_GCM_TAG_LEN];
        let mbuf = unsafe { from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };
        generated_auth_id.put_u16(data.len() as u16);
        cipher.encrypt_inplace_with_slice(nonce, &generated_auth_id[..id_len], mbuf);
        unsafe { generated_auth_id.advance_mut(AES_128_GCM_TAG_LEN) };
    }
    generated_auth_id.put_slice(&connection_nonce);
    {
        let payload_header_aead_key = vmess_kdf_3_one_shot(
            cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
            &generated_auth_id[..id_len],
            &connection_nonce,
        );
        let payload_header_aead_nonce = vmess_kdf_3_one_shot(
            cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
            &generated_auth_id[..id_len],
            &connection_nonce,
        );
        let nonce = &payload_header_aead_nonce[..12];
        let cipher = Aes128Gcm::new_with_slice(&payload_header_aead_key[0..16]);
        let mbuf = &mut generated_auth_id.chunk_mut()[..data.len() + AES_128_GCM_TAG_LEN];
        let mbuf = unsafe { from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };
        generated_auth_id.put_slice(data);
        cipher.encrypt_inplace_with_slice(nonce, &generated_auth_id[..id_len], mbuf);
        unsafe { generated_auth_id.advance_mut(AES_128_GCM_TAG_LEN) };
    }
    generated_auth_id
}
