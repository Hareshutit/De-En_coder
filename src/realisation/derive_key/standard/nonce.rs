#[derive(Debug, Clone)]
pub struct StandardNonce(pub [u8; 12]);
impl crate::abstraction::NonceProvider for StandardNonce {
    type Error = super::error::StandardError;
    const NONCE_SIZE: usize = 12;
    fn generate(password: &str, salt: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let digest = hasher.finalize(); // 32 байта
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&digest[..12]);
        Ok(StandardNonce(nonce))
    }
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let mut arr = [0u8; Self::NONCE_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}