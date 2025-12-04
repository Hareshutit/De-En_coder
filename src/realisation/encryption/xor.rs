use crate::abstraction::Encryption;
#[derive(Debug)]
pub struct XorEncryption {
    pub key: Vec<u8>,
}
impl Encryption for XorEncryption {
    type Key = Vec<u8>;
    fn new(key: Self::Key) -> Self {
        Self { key }
    }
    fn encode(&self, buf: &mut [u8]) {
        let key_len = self.key.len();
        if key_len == 0 {
            return;
        }
        for (i, byte) in buf.iter_mut().enumerate() {
            let key_byte = self.key[i % key_len];
            *byte ^= key_byte;
        }
    }
    fn decode(&self, buf: &mut [u8]) {
        let key_len = self.key.len();
        if key_len == 0 {
            return;
        }
        for (i, byte) in buf.iter_mut().enumerate() {
            let key_byte = self.key[i % key_len];
            *byte ^= key_byte;
        }
    }
}