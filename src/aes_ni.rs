use std::{arch::asm, fmt::Debug, mem::MaybeUninit};

use crate::{aes::AESkey, mode::BlockCipher};

pub struct CPUID {
    eax: u32,
    ebx: u32,
    edx: u32,
    ecx: u32,
}

impl Debug for CPUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("CPUID {{ eax: 0x{:x}, ebx: 0x{:x}, edx: 0x{:x}, ecx: 0x{:x} }}", self.eax, self.ebx, self.edx, self.ecx))
    }
}

pub unsafe fn cpuid(in_eax: u32) -> CPUID {
    let eax;
    let ebx;
    let edx;
    let ecx;
    asm!(
        "push rbx",
        "cpuid",
        "mov {r:e}, ebx",
        "pop rbx",
        r = out(reg) ebx,
        inout("eax") in_eax => eax,
        out("edx") edx,
        out("ecx") ecx,
    );
    CPUID { eax, ebx, edx, ecx }
}

pub fn support_aesni() -> bool {
    unsafe {
        let c = cpuid(0);
        if c.eax < 1 {
            false
        } else {
            let d = cpuid(1);
            d.ecx & (1 << 25) != 0
        }
    }
}

pub struct AES_NI {
    round_key: Box<[u8]>,
    inv_round_key: Box<[u8]>,
}

impl AES_NI {
    pub fn new(key: AESkey) -> Self {
        unsafe {
            match key {
                AESkey::K128(v) => {
                    let k = aes_keygen_128(&v as *const [u8] as *const u8);
                    let l = aes_inv_keygen_128(&k);
                    Self { round_key: k, inv_round_key: l }
                }
                _ => todo!()
            }
        }
    }
}

impl BlockCipher<16> for AES_NI {
    fn _encrypt(&self, in_bytes: [u8; 16]) -> [u8; 16] {
        let mut v = in_bytes;
        let ptr = v.as_mut_ptr() as *mut u8;
        let kptr = self.round_key.as_ptr() as *const u8;
        if self.round_key.len() == 0xb0 {
            unsafe { aes_enc_128(ptr, kptr) }
        } else {
            todo!()
        }
        v
    }

    fn _decrypt(&self, in_bytes: [u8; 16]) -> [u8; 16] {
        let mut v = in_bytes;
        let ptr = v.as_mut_ptr() as *mut u8;
        let kptr = self.inv_round_key.as_ptr() as *const u8;
        if self.round_key.len() == 0xb0 {
            unsafe { aes_dec_128(ptr, kptr) }
        } else {
            todo!()
        }
        v
    }
}

unsafe fn aes_keygen_128(key: *const u8) -> Box<[u8]> {
    let mut v: Vec<MaybeUninit<u8>> = vec![MaybeUninit::uninit(); 0xb0];
    asm!(
        "movdqu xmm1, [{k}]",
        "movdqu [{v}], xmm1",

        "aeskeygenassist xmm2, xmm1, 0x1",
        "call 2f",
        "movdqu [{v}+0x10], xmm1",
        "aeskeygenassist xmm2, xmm1, 0x2",
        "call 2f",
        "movdqu [{v}+0x20], xmm1",
        "aeskeygenassist xmm2, xmm1, 0x4",
        "call 2f",
        "movdqu [{v}+0x30], xmm1",
        "aeskeygenassist xmm2, xmm1, 0x8",
        "call 2f",
        "movdqu [{v}+0x40], xmm1",
        "aeskeygenassist xmm2, xmm1, 0x10",
        "call 2f",
        "movdqu [{v}+0x50], xmm1",
        "aeskeygenassist xmm2, xmm1, 0x20",
        "call 2f",
        "movdqu [{v}+0x60], xmm1",
        "aeskeygenassist xmm2, xmm1, 0x40",
        "call 2f",
        "movdqu [{v}+0x70], xmm1",
        "aeskeygenassist xmm2, xmm1, 0x80",
        "call 2f",
        "movdqu [{v}+0x80], xmm1",
        "aeskeygenassist xmm2, xmm1, 0x1b",
        "call 2f",
        "movdqu [{v}+0x90], xmm1",
        "aeskeygenassist xmm2, xmm1, 0x36",
        "call 2f",
        "movdqu [{v}+0xa0], xmm1",

        "jmp 3f",

        "2:",
        "pshufd xmm2, xmm2, 0xff",
        "vpslldq xmm3, xmm1, 0x4",
        "pxor xmm1, xmm3",
        "vpslldq xmm3, xmm1, 0x4",
        "pxor xmm1, xmm3",
        "vpslldq xmm3, xmm1, 0x4",
        "pxor xmm1, xmm3",
        "pxor xmm1, xmm2",
        "ret",

        "3:",
        k = in(reg) key,
        v = in(reg) v.as_mut_ptr(),
        out("xmm1") _,
        out("xmm2") _,
        out("xmm3") _,
    );
    core::mem::transmute::<_, Vec<u8>>(v).into_boxed_slice()
}

unsafe fn aes_inv_keygen_128(data: &Box<[u8]>) -> Box<[u8]> {
    let mut v: Vec<MaybeUninit<u8>> = vec![MaybeUninit::uninit(); 0xb0];
    asm!(
        "movdqu xmm0, [{k}]",
        "movdqu [{d}], xmm0",

        "aesimc xmm0, [{k}+0x10]",
        "movdqu [{d}+0x10], xmm0",
        "aesimc xmm0, [{k}+0x20]",
        "movdqu [{d}+0x20], xmm0",
        "aesimc xmm0, [{k}+0x30]",
        "movdqu [{d}+0x30], xmm0",
        "aesimc xmm0, [{k}+0x40]",
        "movdqu [{d}+0x40], xmm0",
        "aesimc xmm0, [{k}+0x50]",
        "movdqu [{d}+0x50], xmm0",
        "aesimc xmm0, [{k}+0x60]",
        "movdqu [{d}+0x60], xmm0",
        "aesimc xmm0, [{k}+0x70]",
        "movdqu [{d}+0x70], xmm0",
        "aesimc xmm0, [{k}+0x80]",
        "movdqu [{d}+0x80], xmm0",
        "aesimc xmm0, [{k}+0x90]",
        "movdqu [{d}+0x90], xmm0",

        "movdqu xmm0, [{k}+0xa0]",
        "movdqu [{d}+0xa0], xmm0",
        k = in(reg) data.as_ptr(),
        d = in(reg) v.as_mut_ptr(),
        out("xmm0") _,
    );
    core::mem::transmute::<_, Vec<u8>>(v).into_boxed_slice()
}

unsafe fn aes_enc_128(data: *mut u8, key: *const u8) {
    asm!(
        "movdqu xmm0, [{d}]",
        "pxor xmm0, [{k}]",
        "aesenc xmm0, [{k}+16]",
        "aesenc xmm0, [{k}+32]",
        "aesenc xmm0, [{k}+48]",
        "aesenc xmm0, [{k}+64]",
        "aesenc xmm0, [{k}+80]",
        "aesenc xmm0, [{k}+96]",
        "aesenc xmm0, [{k}+112]",
        "aesenc xmm0, [{k}+128]",
        "aesenc xmm0, [{k}+144]",
        "aesenclast xmm0, [{k}+160]",
        "movdqu [{d}], xmm0",
        d = in(reg) data,
        k = in(reg) key,
        out("xmm0") _,
    )
}

unsafe fn aes_dec_128(data: *mut u8, inv_key: *const u8) {
    asm!(
        "movdqu xmm0, [{d}]",
        "pxor xmm0, [{k}+0xa0]",
        "aesdec xmm0, [{k}+0x90]",
        "aesdec xmm0, [{k}+0x80]",
        "aesdec xmm0, [{k}+0x70]",
        "aesdec xmm0, [{k}+0x60]",
        "aesdec xmm0, [{k}+0x50]",
        "aesdec xmm0, [{k}+0x40]",
        "aesdec xmm0, [{k}+0x30]",
        "aesdec xmm0, [{k}+0x20]",
        "aesdec xmm0, [{k}+0x10]",
        "aesdeclast xmm0, [{k}]",
        "movdqu [{d}], xmm0",
        d = in(reg) data,
        k = in(reg) inv_key,
    )
}


#[cfg(test)]
mod test {
    use crate::{aes_ni::AES_NI, aes::AESkey, mode::BlockCipher};

    #[test]
    fn encrypt() {
        let a = AES_NI::new(
            AESkey::K128(*b"!\xf4\x02\xf2[\x1a\x0f\xd7\"\xb81i\xe1\x05\t\xf8")
        );
        assert_eq!(a._encrypt(*b"s\xdf\xffW\xfe$\xe8\x07\xbdO\xb1\xbcN\x07\xcds"), *b"\x9c)\xe4l\xf1\xce\x04\xe8=:k\x16{{\xe1J");

        let b = AES_NI::new(
            AESkey::K192(*b"\x01kG\xc4\xa2XI\nRA\xea\xc9m\xde\x81\xb8\"\xbd \xd5_\xa2A\x0e")
        );
        assert_eq!(b._encrypt(*b"s\xdf\xffW\xfe$\xe8\x07\xbdO\xb1\xbcN\x07\xcds"), *b"\xfa\xe3\xc6v\x8f\x90Xj>Rg,b\x05\xca\xb4");

        let c = AES_NI::new(
            AESkey::K256(*b"\xa8\x19@\x8c\xe5\x01\x0c\xa2\xe0\x9e\xf5\x9a\xc3\xd8\x9f_\xf8Y]\x02\xb5$\xe6\x1b\xf8\xaf\xa8\x94\xa9]YO")
        );
        assert_eq!(c._encrypt(*b"s\xdf\xffW\xfe$\xe8\x07\xbdO\xb1\xbcN\x07\xcds"), *b"e\x13\xa2\xa4\xc7R\xca@3\xc0\xde\xf6\xab:\xe8\xcb");
    }

    #[test]
    fn decrypt() {
        let ans = *b"s\xdf\xffW\xfe$\xe8\x07\xbdO\xb1\xbcN\x07\xcds";
        let a = AES_NI::new(
            AESkey::K128(*b"!\xf4\x02\xf2[\x1a\x0f\xd7\"\xb81i\xe1\x05\t\xf8")
        );
        assert_eq!(a._decrypt(*b"\x9c)\xe4l\xf1\xce\x04\xe8=:k\x16{{\xe1J"), ans);

        let b = AES_NI::new(
            AESkey::K192(*b"\x01kG\xc4\xa2XI\nRA\xea\xc9m\xde\x81\xb8\"\xbd \xd5_\xa2A\x0e")
        );
        assert_eq!(b._decrypt(*b"\xfa\xe3\xc6v\x8f\x90Xj>Rg,b\x05\xca\xb4"), ans);

        let c = AES_NI::new(
            AESkey::K256(*b"\xa8\x19@\x8c\xe5\x01\x0c\xa2\xe0\x9e\xf5\x9a\xc3\xd8\x9f_\xf8Y]\x02\xb5$\xe6\x1b\xf8\xaf\xa8\x94\xa9]YO")
        );
        assert_eq!(c._decrypt(*b"e\x13\xa2\xa4\xc7R\xca@3\xc0\xde\xf6\xab:\xe8\xcb"), ans);
    }
}
