use std::{ops::BitXor, array};

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
struct Word {
    inner: [u8; 4]
}

impl Word {
    fn rot(self) -> Self {
        Word { inner: array::from_fn(|i| self.inner[(i + 1) % 4]) }
    }
    fn sub(self) -> Self {
        Word { inner: array::from_fn(|i| S_BOX[self.inner[i] as usize]) }
    }
}

impl BitXor for Word {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut w = Word { inner: [0; 4] };
        for i in 0..4 {
            w.inner[i] = self.inner[i] ^ rhs.inner[i];
        }
        w
    }
}


#[derive(Debug)]
enum AESkey {
    K128([u8; 16]),
    K192([u8; 24]),
    K256([u8; 32]),
}

impl AESkey {
    fn key_expansion(&self) -> (usize, Box<[[u8; 16]]>) {
        match self {
            AESkey::K128(k) => (11, AESkey::key_expansion_inner(11, &k[..], 4)),
            AESkey::K192(k) => (13, AESkey::key_expansion_inner(13, &k[..], 6)),
            AESkey::K256(k) => (15, AESkey::key_expansion_inner(15, &k[..], 8)),
        }
    }
    fn key_expansion_inner(r: usize, k: &[u8], n: usize) -> Box<[[u8; 16]]> {
        let mut w = vec![Word {inner: [0; 4]}; 4 * r];

        for i in 0..4 * r {
            if i < n {
                for (j, iv) in w[i].inner.iter_mut().enumerate() {
                    *iv = k[4 * i + j];
                }
            } else if i % n == 0 {
                w[i] = w[i - n] ^ w[i - 1].rot().sub() ^ Word { inner: [RC[i / n - 1], 0, 0, 0] }
            } else if n > 6 && i % n == 4 {
                w[i] = w[i - n] ^ w[i - 1].sub();
            } else {
                w[i] = w[i - n] ^ w[i - 1];
            }
        }

        let mut res = vec![[0u8; 16]; r];
        for i in 0..r {
            for j in 0..4 {
                for l in 0..4 {
                    res[i][4 * j + l] = w[4 * i + j].inner[l];
                }
            }
        }
        res.into_boxed_slice()
    }
}

#[derive(Debug)]
struct AES {
    bytes: [u8; 16],
    key: AESkey,
}

impl AES {
    #[inline]
    fn add_round_key(b: [u8; 16], k: [u8; 16]) -> [u8; 16] {
        let mut tmp = [0; 16];
        for i in 0..16 {
            tmp[i] = b[i] ^ k[i];
        }
        tmp
    }
    #[inline]
    fn sub_bytes(b: [u8; 16]) -> [u8; 16] {
        let mut tmp = [0; 16];
        for i in 0..16 {
            tmp[i] = S_BOX[b[i] as usize];
        }
        tmp
    }
    #[inline]
    fn shift_rows(b: [u8; 16]) -> [u8; 16] {
        let mut tmp = [0; 16];
        for i in 0..4 {
            for j in 0..4 {
                tmp[4 * j + i] = b[(4 * j + 5 * i) % 16];
            }
        }
        tmp
    }
    #[inline]
    fn mix_columns(b: [u8; 16]) -> [u8; 16] {
        const VECTOR: [u8; 4] = [2, 3, 1, 1];
        let mut tmp = [0; 16];
        for col in 0..4 {
            for row in 0..4 {
                for c in 0..4 {
                    tmp[4 * col + row] ^= mul(VECTOR[(c + 4 - row) % 4], b[4 * col + c]);
                }
            }
        }
        tmp
    }

    fn encrypt(&self) -> [u8; 16] {
        let (round, keys) = self.key.key_expansion();
        let mut bytes = AES::add_round_key(self.bytes, keys[0]);

        for i in 1..round - 1 {
            bytes = AES::add_round_key(AES::mix_columns(AES::shift_rows(AES::sub_bytes(bytes))), keys[i]);
        }
        AES::add_round_key(AES::shift_rows(AES::sub_bytes(bytes)), keys[round - 1])
    }
}

#[cfg(test)]
mod test {
    use crate::AES;
    use crate::AESkey;

    #[test]
    fn mix_columns() {
        let v = [0xdbu8, 0x13, 0x53, 0x45, 0xf2, 0x0a, 0x22, 0x5c, 0x1, 0x1, 0x1, 0x1, 0x2d, 0x26, 0x31, 0x4c];
        let res = AES::mix_columns(v);
        let ans = [0x8eu8, 0x4d, 0xa1, 0xbc, 0x9f, 0xdc, 0x58, 0x9d, 0x1, 0x1, 0x1, 0x1, 0x4d, 0x7e, 0xbd, 0xf8];
        assert_eq!(res, ans);
    }

    #[test]
    fn encrypt() {
        let a = AES {
            bytes: *b"s\xdf\xffW\xfe$\xe8\x07\xbdO\xb1\xbcN\x07\xcds",
            key: AESkey::K128(*b"!\xf4\x02\xf2[\x1a\x0f\xd7\"\xb81i\xe1\x05\t\xf8")
        };
        assert_eq!(a.encrypt(), *b"\x9c)\xe4l\xf1\xce\x04\xe8=:k\x16{{\xe1J");

        let b = AES {
            bytes: *b"s\xdf\xffW\xfe$\xe8\x07\xbdO\xb1\xbcN\x07\xcds",
            key: AESkey::K192(*b"\x01kG\xc4\xa2XI\nRA\xea\xc9m\xde\x81\xb8\"\xbd \xd5_\xa2A\x0e")
        };
        assert_eq!(b.encrypt(), *b"\xfa\xe3\xc6v\x8f\x90Xj>Rg,b\x05\xca\xb4");

        let c = AES {
            bytes: *b"s\xdf\xffW\xfe$\xe8\x07\xbdO\xb1\xbcN\x07\xcds",
            key: AESkey::K256(*b"\xa8\x19@\x8c\xe5\x01\x0c\xa2\xe0\x9e\xf5\x9a\xc3\xd8\x9f_\xf8Y]\x02\xb5$\xe6\x1b\xf8\xaf\xa8\x94\xa9]YO")
        };
        assert_eq!(c.encrypt(), *b"e\x13\xa2\xa4\xc7R\xca@3\xc0\xde\xf6\xab:\xe8\xcb");
    }
}

fn main() {
    let i = AES { bytes: [0x11; 16], key: AESkey::K128([0x22; 16]) };
    let j = i.encrypt();
    println!("{:?}", j);
}
