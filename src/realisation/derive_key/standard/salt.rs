
pub mod error;

const STANDARD_SALT_SIZE: usize = 16;

#[derive(Debug, Clone)]
pub struct StandardSalt {
    value: [u8; STANDARD_SALT_SIZE],
}
impl crate::abstraction::SaltProvider for StandardSalt {
    type Error = error::SaltError;
    const SALT_SIZE: usize = STANDARD_SALT_SIZE;
    fn generate() -> Result<Self, Self::Error> {
        let mut salt = [0u8; Self::SALT_SIZE];
        getrandom::fill(&mut salt).map_err(crate::realisation::derive_key::standard::error::StandardError::RandomFailed).map_err(|e| error::SaltError)?;
        Ok(StandardSalt { value: salt })
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != Self::SALT_SIZE {
            return Err(error::SaltError);
        }
        let mut value = [0u8; Self::SALT_SIZE];
        value.copy_from_slice(bytes);
        Ok(Self { value })
    }
    fn as_bytes(&self) -> &[u8] {
        &self.value
    }
}
