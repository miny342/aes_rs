use std::array;

pub trait BlockCipher<const TEXT_SIZE: usize> {
    fn _encrypt(&self, in_bytes: [u8; TEXT_SIZE]) -> [u8; TEXT_SIZE];
    fn _decrypt(&self, in_bytes: [u8; TEXT_SIZE]) -> [u8; TEXT_SIZE];

    #[doc(hidden)]
    fn _assert1(&self, ib_len: usize) {
        if ib_len % TEXT_SIZE != 0 {
            panic!("in_bytesの大きさは{}の倍数である必要があります", TEXT_SIZE);
        }
    }

    #[doc(hidden)]
    fn _assert2(&self, ib_len: usize, ob_len: usize) {
        if ib_len != ob_len {
            panic!("in_bytesとout_bytesの長さは同じである必要があります");
        }
    }

    fn encrypt_ecb(&self, in_bytes: &[u8], out_bytes: &mut [u8]) {
        self._assert1(in_bytes.len());
        self._assert2(in_bytes.len(), out_bytes.len());
        for (i, v) in in_bytes.windows(TEXT_SIZE).step_by(TEXT_SIZE).enumerate() {
            out_bytes[TEXT_SIZE * i..TEXT_SIZE * (i + 1)].copy_from_slice(&self._encrypt(v.try_into().unwrap()))
        }
    }
    fn decrypt_ecb(&self, in_bytes: &[u8], out_bytes: &mut [u8]) {
        self._assert1(in_bytes.len());
        self._assert2(in_bytes.len(), out_bytes.len());
        for (i, v) in in_bytes.windows(TEXT_SIZE).step_by(TEXT_SIZE).enumerate() {
            out_bytes[TEXT_SIZE * i..TEXT_SIZE * (i + 1)].copy_from_slice(&self._decrypt(v.try_into().unwrap()))
        }
    }

    fn encrypt_cbc(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE], out_bytes: &mut [u8]) {
        self._assert1(in_bytes.len());
        self._assert2(in_bytes.len(), out_bytes.len());
        out_bytes[0..TEXT_SIZE].copy_from_slice(&self._encrypt(array::from_fn(|i| in_bytes[i] ^ iv[i])));
        for (i, v) in in_bytes[TEXT_SIZE..].windows(TEXT_SIZE).step_by(TEXT_SIZE).enumerate() {
            let (l, r) = out_bytes.split_at_mut((i + 1) * TEXT_SIZE);
            r[0..TEXT_SIZE].copy_from_slice(&self._encrypt(array::from_fn(|j| v[j] ^ l[i * TEXT_SIZE + j])))
        }
    }
    fn decrypt_cbc(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE], out_bytes: &mut [u8]) {
        self._assert1(in_bytes.len());
        self._assert2(in_bytes.len(), out_bytes.len());
        let mut dec = self._decrypt(in_bytes[0..TEXT_SIZE].try_into().unwrap());
        out_bytes[0..TEXT_SIZE].copy_from_slice(&array::from_fn::<u8, TEXT_SIZE, _>(|i| dec[i] ^ iv[i]));
        for (i, v) in in_bytes.windows(TEXT_SIZE * 2).step_by(TEXT_SIZE).enumerate() {
            dec = self._decrypt(v[TEXT_SIZE..TEXT_SIZE * 2].try_into().unwrap());
            out_bytes[(i + 1) * TEXT_SIZE..(i + 2) * TEXT_SIZE].copy_from_slice(&array::from_fn::<u8, TEXT_SIZE, _>(|j| dec[j] ^ v[j]));
        }
    }

    fn encrypt_ofb(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE], out_bytes: &mut [u8]) {
        self._assert2(in_bytes.len(), out_bytes.len());
        let mut e = iv;
        for (i, (ib, ob)) in in_bytes.iter().zip(out_bytes.iter_mut()).enumerate() {
            if i % TEXT_SIZE == 0 {
                e = self._encrypt(e);
            }
            *ob = *ib ^ e[i % TEXT_SIZE];
        }
    }
    fn decrypt_ofb(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE], out_bytes: &mut [u8]) {
        self.encrypt_ofb(in_bytes, iv, out_bytes)
    }

    #[doc(hidden)]
    fn _cfb_n(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE], out_bytes: &mut [u8], n: usize, is_encrypt: bool) {
        self._assert2(in_bytes.len(), out_bytes.len());
        if n % 8 != 0 {
            panic!("nは8の倍数にしてください");
        }
        let mut e = iv;
        let mut e1 = iv;
        let block = n / 8;
        for (i, (ib, ob)) in in_bytes.iter().zip(out_bytes.iter_mut()).enumerate() {
            if i % block == 0 {
                e1 = self._encrypt(e);
                e.copy_within(block.., 0);
            }
            *ob = e1[i % block] ^ *ib;
            e[TEXT_SIZE - block + (i % block)] = if is_encrypt { *ob } else { *ib };
        }
    }
    fn encrypt_cfb(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE], out_bytes: &mut [u8]) {
        self._cfb_n(in_bytes, iv, out_bytes, TEXT_SIZE * 8, true);
    }
    fn decrypt_cfb(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE], out_bytes: &mut [u8]) {
        self._cfb_n(in_bytes, iv, out_bytes, TEXT_SIZE * 8, false);
    }
    fn encrypt_cfb_n(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE], out_bytes: &mut [u8], n: usize) {
        self._cfb_n(in_bytes, iv, out_bytes, n, true);
    }
    fn decrypt_cfb_n(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE], out_bytes: &mut [u8], n: usize) {
        self._cfb_n(in_bytes, iv, out_bytes, n, false)
    }

    fn encrypt_ctr(&self, in_bytes: &[u8], nonce: &[u8], out_bytes: &mut [u8]) {
        self._assert2(in_bytes.len(), out_bytes.len());
        if nonce.len() >= TEXT_SIZE {
            panic!("nonceは長さを{}未満にしてください", TEXT_SIZE);
        }
        let mut e = [0; TEXT_SIZE];
        let mut c: DefaultCounter<TEXT_SIZE> = DefaultCounter::new(nonce);
        for (i, (ib, ob)) in in_bytes.iter().zip(out_bytes.iter_mut()).enumerate() {
            if i % TEXT_SIZE == 0 {
                e = self._encrypt(c.inner);
                c.next();
            }
            *ob = *ib ^ e[i % TEXT_SIZE];
        }
    }
    fn decrypt_ctr(&self, in_bytes: &[u8], nonce: &[u8], out_bytes: &mut [u8]) {
        self.encrypt_ctr(in_bytes, nonce, out_bytes);
    }
}

struct DefaultCounter<const T: usize> {
    inner: [u8; T],
    nonce_len: usize,
}

impl<const T: usize> DefaultCounter<T> {
    fn new(nonce: &[u8]) -> Self {
        Self { inner: array::from_fn(|i| if i < nonce.len() { nonce[i] } else {0}), nonce_len: nonce.len() }
    }
    fn next(&mut self) {
        for i in 1..=T - self.nonce_len {
            let b;
            (self.inner[T - i], b) = self.inner[T - i].overflowing_add(1);
            if !b { return; }
        }
        panic!("counter overflow");
    }
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

    use super::{BlockCipherTester, BlockCipher, DefaultCounter};

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
        let res: [u8; 14] = array::from_fn(|i| i as u8);
        let mut out_bytes = [0; 14];
        let mut out_out_bytes = [0; 14];
        let iv = [11, 12, 13, 14];
        b.encrypt_ofb(&res, iv, &mut out_bytes);
        b.decrypt_ofb(&out_bytes, iv, &mut out_out_bytes);
        assert!(out_out_bytes == res);
    }

    #[test]
    fn test_cfb() {
        let b = BlockCipherTester;
        let res: [u8; 13] = array::from_fn(|i| i as u8);
        let mut out_bytes = [0; 13];
        let mut out_out_bytes = [0; 13];
        let iv = [11, 12, 13, 14];
        b.encrypt_cfb(&res, iv, &mut out_bytes);
        b.decrypt_cfb(&out_bytes, iv, &mut out_out_bytes);
        assert!(out_out_bytes == res);
    }

    #[test]
    fn test_cfb_n() {
        let b = BlockCipherTester;
        let res: [u8; 13] = array::from_fn(|i| i as u8);
        let mut out_bytes = [0; 13];
        let mut out_out_bytes = [0; 13];
        let iv = [11, 12, 13, 14];
        b.encrypt_cfb_n(&res, iv, &mut out_bytes, 24);
        b.decrypt_cfb_n(&out_bytes, iv, &mut out_out_bytes, 24);
        assert!(out_out_bytes == res);
    }

    #[test]
    fn test_ctr() {
        let b = BlockCipherTester;
        let res: [u8; 20] = array::from_fn(|i| i as u8);
        let mut out_bytes = [0; 20];
        let mut out_out_bytes = [0; 20];
        let nonce = [11, 12, 13];
        b.encrypt_ctr(&res, &nonce, &mut out_bytes);
        b.decrypt_ctr(&out_bytes, &nonce, &mut out_out_bytes);
        assert!(out_out_bytes == res);
    }
}
