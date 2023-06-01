use std::array;

pub trait BlockCipher<const TEXT_SIZE: usize> {
    fn _encrypt(&self, in_bytes: [u8; TEXT_SIZE]) -> [u8; TEXT_SIZE];
    fn _decrypt(&self, in_bytes: [u8; TEXT_SIZE]) -> [u8; TEXT_SIZE];

    #[doc(hidden)]
    fn _prologue(&self, in_bytes: &[u8], out_bytes: &mut [u8]) {
        if in_bytes.len() % TEXT_SIZE != 0 {
            panic!("in_bytesの大きさは{}の倍数である必要があります", TEXT_SIZE);
        }
        if in_bytes.len() != out_bytes.len() {
            panic!("in_bytesとout_bytesの長さは同じである必要があります");
        }
    }

    fn encrypt_ecb(&self, in_bytes: &[u8], out_bytes: &mut [u8]) {
        self._prologue(in_bytes, out_bytes);
        for (i, v) in in_bytes.windows(TEXT_SIZE).step_by(TEXT_SIZE).enumerate() {
            out_bytes[TEXT_SIZE * i..TEXT_SIZE * (i + 1)].copy_from_slice(&self._encrypt(v.try_into().unwrap()))
        }
    }
    fn decrypt_ecb(&self, in_bytes: &[u8], out_bytes: &mut [u8]) {
        self._prologue(in_bytes, out_bytes);
        for (i, v) in in_bytes.windows(TEXT_SIZE).step_by(TEXT_SIZE).enumerate() {
            out_bytes[TEXT_SIZE * i..TEXT_SIZE * (i + 1)].copy_from_slice(&self._decrypt(v.try_into().unwrap()))
        }
    }
    fn encrypt_cbc(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE], out_bytes: &mut [u8]) {
        self._prologue(in_bytes, out_bytes);
        out_bytes[0..TEXT_SIZE].copy_from_slice(&self._encrypt(array::from_fn(|i| in_bytes[i] ^ iv[i])));
        for (i, v) in in_bytes[TEXT_SIZE..].windows(TEXT_SIZE).step_by(TEXT_SIZE).enumerate() {
            let (l, r) = out_bytes.split_at_mut((i + 1) * TEXT_SIZE);
            r[0..TEXT_SIZE].copy_from_slice(&self._encrypt(array::from_fn(|j| v[j] ^ l[i * TEXT_SIZE + j])))
        }
    }
    fn decrypt_cbc(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE], out_bytes: &mut [u8]) {
        self._prologue(in_bytes, out_bytes);
        let mut dec = self._decrypt(in_bytes[0..TEXT_SIZE].try_into().unwrap());
        out_bytes[0..TEXT_SIZE].copy_from_slice(&array::from_fn::<u8, TEXT_SIZE, _>(|i| dec[i] ^ iv[i]));
        for (i, v) in in_bytes.windows(TEXT_SIZE * 2).step_by(TEXT_SIZE).enumerate() {
            dec = self._decrypt(v[TEXT_SIZE..TEXT_SIZE * 2].try_into().unwrap());
            out_bytes[(i + 1) * TEXT_SIZE..(i + 2) * TEXT_SIZE].copy_from_slice(&array::from_fn::<u8, TEXT_SIZE, _>(|j| dec[j] ^ v[j]));
        }
    }
    fn encrypt_ofb(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE], out_bytes: &mut [u8]) {
        self._prologue(in_bytes, out_bytes);
        let mut e = iv;
        for (i, v) in in_bytes.windows(TEXT_SIZE).step_by(TEXT_SIZE).enumerate() {
            e = self._encrypt(e);
            out_bytes[i * TEXT_SIZE..(i + 1) * TEXT_SIZE].copy_from_slice(&array::from_fn::<u8, TEXT_SIZE, _>(|j| e[j] ^ v[j]))
        }
    }
    fn decrypt_ofb(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE], out_bytes: &mut [u8]) {
        self.encrypt_ofb(in_bytes, iv, out_bytes)
    }
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
        let res: [u8; 16] = array::from_fn(|i| i as u8);
        let mut out_bytes = [0; 16];
        let mut out_out_bytes = [0; 16];
        b.encrypt_ecb(&res, &mut out_bytes);
        b.decrypt_ecb(&out_bytes, &mut out_out_bytes);
        assert!(res == out_out_bytes);
    }

    #[test]
    fn test_cbc() {
        let b = BlockCipherTester;
        let res: [u8; 16] = array::from_fn(|i| i as u8);
        let mut out_bytes = [0; 16];
        let mut out_out_bytes = [0; 16];
        let iv = [11, 12, 13, 14];
        b.encrypt_cbc(&res, iv, &mut out_bytes);
        b.decrypt_cbc(&out_bytes, iv, &mut out_out_bytes);
        assert!(out_out_bytes == res);
    }

    #[test]
    fn test_ofb() {
        let b = BlockCipherTester;
        let res: [u8; 16] = array::from_fn(|i| i as u8);
        let mut out_bytes = [0; 16];
        let mut out_out_bytes = [0; 16];
        let iv = [11, 12, 13, 14];
        b.encrypt_ofb(&res, iv, &mut out_bytes);
        b.decrypt_ofb(&out_bytes, iv, &mut out_out_bytes);
        assert!(out_out_bytes == res);
    }
}
