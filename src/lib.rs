#![cfg_attr(feature = "use_nightly", feature(portable_simd))]

pub mod aes;
pub mod mode;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod aes_ni;
