pub trait BlockCipher<const TEXT_SIZE: usize> {
    fn encrypt(&self, in_bytes: [u8; TEXT_SIZE]) -> [u8; TEXT_SIZE];
    fn decrypt(&self, in_bytes: [u8; TEXT_SIZE]) -> [u8; TEXT_SIZE];

    fn ecb(&self, in_bytes: &[u8]) -> Box<[u8]>;
    fn cbc(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE]) -> Box<[u8]>;
    fn ofb(&self, in_bytes: &[u8], iv: [u8; TEXT_SIZE]) -> Box<[u8]>;
    fn ctr(&self, in_bytes: &[u8], nonce: [u8; TEXT_SIZE]) -> Box<[u8]>;
}
