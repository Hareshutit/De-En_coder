use crate::abstraction::{SaltProvider, Secret};

pub mod secret;
pub mod salt;
pub mod parametr;
pub mod nonce;
pub mod error;

#[derive(Debug)]
pub struct StandardKdf<const L: usize> {
    params: (),
    salt: salt::StandardSalt,
    secret: secret::StandardKey,
    nonce: nonce::StandardNonce,
}
impl<const L: usize> crate::abstraction::KeyDeriver<String, ()> for StandardKdf<L> {
    type Error = error::StandardError;
    const KEY_LENGTH: usize = L;
    /// Мы не используем параметры в данном генераторе, поэтому указываем `()`.
    type Params = ();
    type Salt = salt::StandardSalt;
    type Secret = secret::StandardKey;
    type Nonce = nonce::StandardNonce;
    fn new(
        secret: Self::Secret,
        _params: Self::Params, // Игнорируем параметры
        salt: Self::Salt,
        nonce: Self::Nonce,
    ) -> Self
    where
        Self: Sized,
    {
        StandardKdf::<L> {
            salt: salt,
            secret: secret,
            params: (),
            nonce: nonce,
        }
    }
    /// Генерирует гамму (keystream) в `buffer`.
    fn derive_key(&self, buffer: &mut [u8]) -> Result<(), Self::Error>
    where
        Self: Sized,
    {
        // Проверяем длину буфера
        if buffer.len() != Self::KEY_LENGTH {
            return Err(Self::Error::LengthMismatch);
        }
        // 1) Построим SHA256(secret and salt)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.secret.as_bytes());
        hasher.update(self.salt.as_bytes());
        let digest = hasher.finalize(); // 32 байта
        // 2) Если KEY_LENGTH <= 32, используем первые KEY_LENGTH байт digest
        //    Если больше, можно расширять при помощи HKDF/DRBG — здесь
        //    мы поддерживаем KEY_LENGTH <= 32 (рекомендация: 32)
        if Self::KEY_LENGTH > 32 {
            // для простоты — не поддерживаем >32 в этой реализации
            return Err(Self::Error::LengthMismatch);
        }
        buffer.copy_from_slice(&digest[..Self::KEY_LENGTH]);
        Ok(())
    }
}