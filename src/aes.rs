use std::{ops::BitXor, array};
use crate::mode::BlockCipher;

// GF(2)[x]/(x^8+x^4+x^3+x+1)上での掛け算
const fn mul(l: u8, r: u8) -> u8 {
    let mut res = 0;
    let mut v = r;
    let mut i = 0;
    while i < 8 {
        if (l >> i) & 1 != 0 {
            res ^= v;
        }
        v = (v << 1) ^ (if v & 0x80 != 0 {0x1b} else {0}); // GF(2)[x]/(x^8+x^4+x^3+x+1)上での2倍
        i += 1;
    }
    res
}

const S_BOX: [u8; 256] = {
    let mut exp_table = [0u8; 256];
    let mut log_table = [0u8; 256];
    let mut i = 0;
    let mut v = 1u8;
    while i < 256 {
        exp_table[i] = v;
        log_table[v as usize] = i as u8;
        i += 1;
        v = mul(3, v);
    }
    let mut sbox = [0; 256];
    sbox[0] = 0x63;
    i = 1;
    while i < 256 {
        let inv = exp_table[255 - log_table[i] as usize];  // 1 / i
        sbox[i] = inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3) ^ inv.rotate_left(4) ^ 0x63;
        i += 1;
    }
    sbox
};

const INV_S_BOX: [u8; 256] = {
    let mut inv = [0; 256];
    let mut i = 0;
    while i < 256 {
        inv[S_BOX[i] as usize] = i as u8;
        i += 1;
    }
    inv
};

const RC: [u8; 10] = {
    let mut arr = [1u8; 10];
    let mut j = 1;
    while j < 10 {
        arr[j] = mul(2, arr[j - 1]);
        j += 1;
    }
    arr
};

#[derive(Clone, Copy)]
struct Word([u8; 4]);

impl Word {
    fn rot(self) -> Self {
        Self(array::from_fn(|i| self.0[(i + 1) % 4]))
    }
    fn sub(self) -> Self {
        Self(array::from_fn(|i| S_BOX[self.0[i] as usize]))
    }
}

impl BitXor for Word {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(array::from_fn(|i| self.0[i] ^ rhs.0[i]))
    }
}

#[derive(Debug)]
pub enum AESkey {
    K128([u8; 16]),
    K192([u8; 24]),
    K256([u8; 32]),
}

impl AESkey {
    fn key_expansion(&self) -> Box<[[u8; 16]]> {
        match self {
            AESkey::K128(k) => AESkey::key_expansion_inner(11, &k[..], 4),
            AESkey::K192(k) => AESkey::key_expansion_inner(13, &k[..], 6),
            AESkey::K256(k) => AESkey::key_expansion_inner(15, &k[..], 8),
        }
    }
    fn key_expansion_inner(r: usize, k: &[u8], n: usize) -> Box<[[u8; 16]]> {
        let mut w: Vec<Word> = Vec::with_capacity(4 * r);
        for i in 0..4 * r {
            let v: Word;
            if i < n {
                v = Word(array::from_fn(|j| k[4 * i + j]));
            } else if i % n == 0 {
                v = w[i - n] ^ w[i - 1].rot().sub() ^ Word([RC[i / n - 1], 0, 0, 0]);
            } else if n > 6 && i % n == 4 {
                v = w[i - n] ^ w[i - 1].sub();
            } else {
                v = w[i - n] ^ w[i - 1];
            }
            w.push(v);
        }

        let mut res = vec![[0u8; 16]; r];
        for i in 0..r {
            for j in 0..4 {
                for l in 0..4 {
                    res[i][4 * j + l] = w[4 * i + j].0[l];
                }
            }
        }
        res.into_boxed_slice()
    }
}

#[derive(Clone)]
struct AESBlock([u8; 16]);

impl From<&[u8]> for AESBlock {
    fn from(value: &[u8]) -> Self {
        assert!(value.len() == 16);
        Self(array::from_fn(|i| value[i]))
    }
}

impl From<&[u8; 16]> for AESBlock {
    fn from(value: &[u8; 16]) -> Self {
        Self(*value)
    }
}

impl From<[u8; 16]> for AESBlock {
    fn from(value: [u8; 16]) -> Self {
        Self(value)
    }
}

impl AESBlock {
    fn add_round_key(&self, k: [u8; 16]) -> Self {
        Self(array::from_fn(|i| self.0[i] ^ k[i]))
    }

    fn sub_bytes(self) -> Self {
        Self(array::from_fn(|i| S_BOX[self.0[i] as usize]))
    }
    fn inv_sub_bytes(self) -> Self {
        Self(array::from_fn(|i| INV_S_BOX[self.0[i] as usize]))
    }

    fn shift_rows(self) -> Self {
        let mut tmp = [0; 16];
        for i in 0..4 {
            for j in 0..4 {
                tmp[4 * j + i] = self.0[(4 * j + 5 * i) % 16];
            }
        }
        Self(tmp)
    }
    fn inv_shift_rows(self) -> Self {
        let mut tmp = [0; 16];
        for i in 0..4 {
            for j in 0..4 {
                tmp[4 * j + i] = self.0[(4 * j + 13 * i) % 16];
            }
        }
        Self(tmp)
    }

    fn mix_columns(self) -> Self {
        const VECTOR: [u8; 4] = [2, 3, 1, 1];
        let mut tmp = [0; 16];
        for col in 0..4 {
            for row in 0..4 {
                for c in 0..4 {
                    tmp[4 * col + row] ^= mul(VECTOR[(c + 4 - row) % 4], self.0[4 * col + c]);
                }
            }
        }
        Self(tmp)
    }
    fn inv_mix_columns(self) -> Self {
        const VECTOR: [u8; 4] = [14, 11, 13, 9];
        let mut tmp = [0; 16];
        for col in 0..4 {
            for row in 0..4 {
                for c in 0..4 {
                    tmp[4 * col + row] ^= mul(VECTOR[(c + 4 - row) % 4], self.0[4 * col + c]);
                }
            }
        }
        Self(tmp)
    }
}

#[derive(Debug)]
pub struct AES {
    round_keys: Box<[[u8; 16]]>
}

impl AES {
    pub fn new(key: AESkey) -> Self {
        Self{ round_keys: key.key_expansion() }
    }
    pub fn encrypt(&self, in_bytes: [u8; 16]) -> [u8; 16] {
        let keys = &self.round_keys;
        let round = keys.len();
        let mut bytes: AESBlock = in_bytes.into();
        bytes = bytes.add_round_key(keys[0]);

        for i in 1..round - 1 {
            bytes = bytes.sub_bytes().shift_rows().mix_columns().add_round_key(keys[i]);
        }
        bytes.sub_bytes().shift_rows().add_round_key(keys[round - 1]).0
    }
    pub fn decrypt(&self, in_bytes: [u8; 16]) -> [u8; 16] {
        let keys = &self.round_keys;
        let round = keys.len();
        let mut bytes: AESBlock = in_bytes.into();
        bytes = bytes.add_round_key(keys[round - 1]).inv_shift_rows().inv_sub_bytes();

        for i in (1..round - 1).rev() {
            bytes = bytes.add_round_key(keys[i]).inv_mix_columns().inv_shift_rows().inv_sub_bytes();
        }
        bytes.add_round_key(keys[0]).0
    }
}

impl BlockCipher<16> for AES {
    fn _encrypt(&self, in_bytes: [u8; 16]) -> [u8; 16] {
        self.encrypt(in_bytes)
    }

    fn _decrypt(&self, in_bytes: [u8; 16]) -> [u8; 16] {
        self.decrypt(in_bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::aes::AES;
    use crate::aes::AESkey;
    use crate::aes::AESBlock;

    #[test]
    fn shift_rows() {
        let v = AESBlock([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        assert_eq!(v.clone().shift_rows().0, [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]);
        assert_eq!(v.clone().inv_shift_rows().0, [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]);
    }

    #[test]
    fn mix_columns() {
        let v = AESBlock([0xdbu8, 0x13, 0x53, 0x45, 0xf2, 0x0a, 0x22, 0x5c, 0x1, 0x1, 0x1, 0x1, 0x2d, 0x26, 0x31, 0x4c]);
        let ans = AESBlock([0x8eu8, 0x4d, 0xa1, 0xbc, 0x9f, 0xdc, 0x58, 0x9d, 0x1, 0x1, 0x1, 0x1, 0x4d, 0x7e, 0xbd, 0xf8]);
        assert_eq!(v.clone().mix_columns().0, ans.0);
        assert_eq!(ans.clone().inv_mix_columns().0, v.0);
    }

    #[test]
    fn encrypt() {
        let a = AES::new(
            AESkey::K128(*b"!\xf4\x02\xf2[\x1a\x0f\xd7\"\xb81i\xe1\x05\t\xf8")
        );
        assert_eq!(a.encrypt(*b"s\xdf\xffW\xfe$\xe8\x07\xbdO\xb1\xbcN\x07\xcds"), *b"\x9c)\xe4l\xf1\xce\x04\xe8=:k\x16{{\xe1J");

        let b = AES::new(
            AESkey::K192(*b"\x01kG\xc4\xa2XI\nRA\xea\xc9m\xde\x81\xb8\"\xbd \xd5_\xa2A\x0e")
        );
        assert_eq!(b.encrypt(*b"s\xdf\xffW\xfe$\xe8\x07\xbdO\xb1\xbcN\x07\xcds"), *b"\xfa\xe3\xc6v\x8f\x90Xj>Rg,b\x05\xca\xb4");

        let c = AES::new(
            AESkey::K256(*b"\xa8\x19@\x8c\xe5\x01\x0c\xa2\xe0\x9e\xf5\x9a\xc3\xd8\x9f_\xf8Y]\x02\xb5$\xe6\x1b\xf8\xaf\xa8\x94\xa9]YO")
        );
        assert_eq!(c.encrypt(*b"s\xdf\xffW\xfe$\xe8\x07\xbdO\xb1\xbcN\x07\xcds"), *b"e\x13\xa2\xa4\xc7R\xca@3\xc0\xde\xf6\xab:\xe8\xcb");
    }

    #[test]
    fn decrypt() {
        let ans = *b"s\xdf\xffW\xfe$\xe8\x07\xbdO\xb1\xbcN\x07\xcds";
        let a = AES::new(
            AESkey::K128(*b"!\xf4\x02\xf2[\x1a\x0f\xd7\"\xb81i\xe1\x05\t\xf8")
        );
        assert_eq!(a.decrypt(*b"\x9c)\xe4l\xf1\xce\x04\xe8=:k\x16{{\xe1J"), ans);

        let b = AES::new(
            AESkey::K192(*b"\x01kG\xc4\xa2XI\nRA\xea\xc9m\xde\x81\xb8\"\xbd \xd5_\xa2A\x0e")
        );
        assert_eq!(b.decrypt(*b"\xfa\xe3\xc6v\x8f\x90Xj>Rg,b\x05\xca\xb4"), ans);

        let c = AES::new(
            AESkey::K256(*b"\xa8\x19@\x8c\xe5\x01\x0c\xa2\xe0\x9e\xf5\x9a\xc3\xd8\x9f_\xf8Y]\x02\xb5$\xe6\x1b\xf8\xaf\xa8\x94\xa9]YO")
        );
        assert_eq!(c.decrypt(*b"e\x13\xa2\xa4\xc7R\xca@3\xc0\xde\xf6\xab:\xe8\xcb"), ans);
    }
}
