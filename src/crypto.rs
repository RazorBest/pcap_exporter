use aes::{Aes128, Aes256};
use cts::{Encrypt, KeyIvInit};
use sha2::Sha256;
use hmac::{Hmac, Mac};
use speck_cipher::Speck48_96;
use speck_cipher::cipher::{BlockEncrypt, KeyInit};

type HmacSha256 = Hmac<Sha256>;

pub struct SecretKeyHmac {
    data: Vec<u8>,
}

impl SecretKeyHmac {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

pub fn hmac256(key: &SecretKeyHmac, data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key.data).expect("HMAC can take key of any size");
    mac.update(data);

    mac.finalize().into_bytes()[..].to_vec()
}

pub fn permute_144_aes_cbccts_r10(key: &[u8], data: [u8; 18]) -> [u8; 18] {
    let key: [u8; 16] = key.try_into().expect("Wrong AES key length");
    let iv = [0x24; 16];
    let mut buf = [0u8; 18];

    let mut msg = data;

    for _ in 0..10 {
        let cipher = cts::CbcCs3Enc::<Aes128>::new(&key.into(), &iv.into());
        cipher.encrypt_b2b(&msg, &mut buf).unwrap();
        msg = buf.clone();
    }

    buf
}

pub fn permute_48_speck48_96(key: &[u8], data: [u8; 6]) -> [u8; 6] {
    let cipher = Speck48_96::new(key.into());
    let mut buf = [0u8; 6];

    cipher.encrypt_block_b2b((&data).into(), (&mut buf).into());

    buf
}

pub fn aes256_ecb(key: &[u8], data: &[u8]) -> Vec<u8> {
    if data.len() % 16 != 0 {
        panic!("ECB can only encrypt messages whose length that are multiple of block length");
    }
    let key: [u8; 32] = key.try_into().expect("Wrong AES key length");
    let cipher = Aes256::new(&key.into());

    let mut enc = data.to_vec();
    for i in (0..data.len()).step_by(16) {
        cipher.encrypt_block((&mut enc[i..i+16]).into());
    }

    enc
}
