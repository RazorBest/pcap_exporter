use core::net::Ipv4Addr;

use crate::crypto::{SecretKeyHmac, aes256_ecb, hmac256, permute_48_speck48_96};

pub type Seed = [u8; 64];

const IPV4_PORT_MASK_KEY_LEN: usize = 12;
const PORT_MASK_KEY_LEN: usize = 32;

struct Ipv4PortMaskKey {
    key: [u8; IPV4_PORT_MASK_KEY_LEN],
}

pub struct Ipv4PortMask {
    key: Ipv4PortMaskKey,
}

impl Ipv4PortMask {
    pub fn new(seed: Seed) -> Self {
        let key = Self::derive_key(seed);

        Self { key }
    }

    /// Derives the secret key used by this class instance, given a seed.
    /// It uses the HKDF from RFC 5869.
    fn derive_key(mut seed: Seed) -> Ipv4PortMaskKey {
        if IPV4_PORT_MASK_KEY_LEN > 32 {
            // Since we only use one hmac256 round
            panic!("Unsupported key length. Too big");
        }

        // HKDF-Extract step from RFC 5869
        let prk = SecretKeyHmac::new(hmac256(
            &SecretKeyHmac::new(b"PcapExport_Ipv4PortMask".to_vec()),
            &seed,
        ));

        let mut key_data = vec![];

        // HKDF-Expand step from RFC 5869
        let mut t1 = hmac256(&prk, b"PcapExport_Ipv4PortInfo\x01");
        key_data.extend_from_slice(&t1[..IPV4_PORT_MASK_KEY_LEN]);

        // Data cleanup
        seed.fill(0);
        t1.fill(0);

        Ipv4PortMaskKey {
            key: key_data.try_into().unwrap(),
        }
    }

    pub fn apply(&self, ipv4: Ipv4Addr, port: u16) -> (Ipv4Addr, u16) {
        let mut data = vec![];
        data.extend_from_slice(&ipv4.octets());
        data.extend_from_slice(&port.to_le_bytes());

        let encrypted = permute_48_speck48_96(&self.key.key, data.try_into().unwrap());

        let new_ipv4: [u8; 4] = encrypted[..4].try_into().unwrap();
        let new_port = u16::from_le_bytes(encrypted[4..].try_into().unwrap());

        (Ipv4Addr::from_octets(new_ipv4), new_port)
    }
}

struct PortMaskKey {
    key: [u8; PORT_MASK_KEY_LEN],
}

pub struct PortMask {
    map: Vec<u16>,
}

impl PortMask {
    pub fn new(seed: Seed) -> Self {
        let key = Self::derive_key(seed);

        Self {
            map: Self::compute_map(key),
        }
    }

    /// Derives the secret key used by this class instance, given a seed.
    /// It uses the HKDF from RFC 5869.
    fn derive_key(mut seed: Seed) -> PortMaskKey {
        if PORT_MASK_KEY_LEN > 32 {
            // Since we only use one hmac256 round
            panic!("Unsupported key length. Too big");
        }

        // HKDF-Extract step from RFC 5869
        let prk = SecretKeyHmac::new(hmac256(
            &SecretKeyHmac::new(b"PcapExport_PortMask".to_vec()),
            &seed,
        ));

        let mut key_data = vec![];

        // HKDF-Expand step from RFC 5869
        let mut t1 = hmac256(&prk, b"PcapExport_PortInfo\x01");
        key_data.extend_from_slice(&t1[..PORT_MASK_KEY_LEN]);

        // Data cleanup
        seed.fill(0);
        t1.fill(0);

        PortMaskKey {
            key: key_data.try_into().unwrap(),
        }
    }

    /// Generates a permutation of all the u16 values as a vector of u16
    fn compute_map(key: PortMaskKey) -> Vec<u16> {
        let mut data = vec![0u8; 16 * (u16::MAX as usize)];

        for x in 0..u16::MAX {
            let b = x.to_le_bytes();
            let i = x as usize;

            data[i * 16] = b[0];
            data[i * 16 + 1] = b[1];
        }

        let data_enc = aes256_ecb(&key.key, &data);
        let (chunks, []) = data_enc.as_chunks::<16>() else {
            panic!("Slices do not divide by 16");
        };

        let mut enc_pairs: Vec<_> = chunks
            .into_iter()
            .enumerate()
            .map(|(i, block)| (block, i as u16))
            .collect();

        enc_pairs.sort();

        let map: Vec<_> = enc_pairs.into_iter().map(|(_, i)| i).collect();

        map
    }

    pub fn apply(&self, port: u16) -> u16 {
        self.map[port as usize]
    }
}
