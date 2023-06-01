use std::array;

pub trait BlockCipher<const TEXT_SIZE: usize> {
    fn _encrypt(&self, in_bytes: [u8; TEXT_SIZE]) -> [u8; TEXT_SIZE];
    fn _decrypt(&self, in_bytes: [u8; TEXT_SIZE]) -> [u8; TEXT_SIZE];

    fn encrypt_ecb(&self, in_bytes: &[u8], out_bytes: &mut [u8]) {
        if in_bytes.len() % TEXT_SIZE != 0 {
            panic!("in_bytesの大きさは{}の倍数である必要があります", TEXT_SIZE);
        }
        if in_bytes.len() != out_bytes.len() {
            panic!("in_bytesとout_bytesの長さは同じである必要があります");
        }
        for (i, v) in in_bytes.windows(TEXT_SIZE).step_by(TEXT_SIZE).enumerate() {
            out_bytes[TEXT_SIZE * i..TEXT_SIZE * (i + 1)].copy_from_slice(&self._encrypt(v.try_into().unwrap()))
        }
    }
    fn decrypt_ecb(&self, in_bytes: &[u8], out_bytes: &mut [u8]) {
        if in_bytes.len() % TEXT_SIZE != 0 {
            panic!("in_bytesの大きさは{}の倍数である必要があります", TEXT_SIZE);
        }
        if in_bytes.len() != out_bytes.len() {
            panic!("in_bytesとout_bytesの長さは同じである必要があります");
        }
        for (i, v) in in_bytes.windows(TEXT_SIZE).step_by(TEXT_SIZE).enumerate() {
            out_bytes[TEXT_SIZE * i..TEXT_SIZE * (i + 1)].copy_from_slice(&self._decrypt(v.try_into().unwrap()))
        }
    }
    fn cbc(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE], out_bytes: &mut [u8]) {}
    fn ofb(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE], out_bytes: &mut [u8]) {}
    fn cfb(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE], out_bytes: &mut [u8]) {}
    fn ctr(&self, in_bytes: &[u8], nonce: [u8; TEXT_SIZE], out_bytes: &mut [u8]) {}
}

struct BlockCipherTester;
impl BlockCipher<4> for BlockCipherTester {
    fn _encrypt(&self, in_bytes: [u8; 4]) -> [u8; 4] {
        array::from_fn(|i| in_bytes[(i + 1) % 4] ^ 0xff)
    }

    fn _decrypt(&self, in_bytes: [u8; 4]) -> [u8; 4] {
        array::from_fn(|i| in_bytes[(i + 3) % 4] ^ 0xff)
    }
}

#[cfg(test)]
mod test {
    use std::array;

    use super::{BlockCipherTester, BlockCipher};

    #[test]
    fn test_ecb() {
        let b = BlockCipherTester;
        let res: [u8; 8] = array::from_fn(|i| i as u8);
        let mut in_bytes: [u8; 8] = array::from_fn(|i| i as u8);
        let mut out_bytes = [0; 8];
        b.encrypt_ecb(&in_bytes, &mut out_bytes);
        b.decrypt_ecb(&out_bytes, &mut in_bytes);
        assert!(res == in_bytes);
    }

    fn test_cbc() {

    }
}
