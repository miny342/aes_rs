// GF(2)[x]/(x^8+x^4+x^3+x+1)上での掛け算
const fn mul(l: u8, r: u8) -> u8 {
    let mut res = 0;
    let mut v = l;
    let mut i = 0;
    while i < 8 {
        if (r >> i) & 1 != 0 {
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
        v = mul(v, 3);
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

fn main() {
    println!("Hello, world!");
    println!("{:?}", INV_S_BOX);
}
