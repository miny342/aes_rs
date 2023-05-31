mod aes;

use crate::aes::{AES, AESkey};

fn main() {
    let i = AES::new(AESkey::K128([0x22; 16]));
    let j = i.encrypt([0x11; 16]);
    let k = i.decrypt(j);
    println!("{:?}", k);
}
