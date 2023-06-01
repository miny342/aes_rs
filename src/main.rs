mod aes;
mod mode;
mod aes_ni;

use crate::{aes::AESkey, mode::BlockCipher};

fn main() {
    let i = AESkey::K128([34,244,2,242,91,26,15,215,34,184,49,105,225,5,9,248]);
    let mut k = [115u8,223,255,87,254,36,232,7,189,79,177,188,78,7,205,115];

    assert!(aes_ni::support_aesni());
    let c = aes_ni::AES_NI::new(i);
    let mut j = [0u8; 16];
    c.encrypt_ecb(&k, &mut j);
    println!("{:?}", j);
    c.decrypt_ecb(&j, &mut k);
    println!("{:?}", k);
}
