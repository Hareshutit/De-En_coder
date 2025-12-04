use crate::{abstraction::Encryption, realisation::encryption::xor::XorEncryption};

pub mod error;
pub mod xor;

/// Форматы шифрования
#[derive(Debug, Clone)]

pub enum CryptoFormat {
    XOR,
    None,
}

impl core::fmt::Display for CryptoFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoFormat::XOR => write!(f, "XOR"),
            CryptoFormat::None => write!(f, "None"),
        }
    }
}

impl core::str::FromStr for CryptoFormat {
    type Err = &'static str; // Тип ошибки, если парсинг не удался
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "xor" => Ok(CryptoFormat::XOR),
            "none" => Ok(CryptoFormat::None),
            _ => Err("Invalid crypto format. Use 'XOR' or 'None'."),
        }
    }
}

impl crate::abstraction::EncryptionList for CryptoFormat {
    type Error = error::Error;

    type Encryptions = EncryptionRealisation;

    fn build(&self, key: &[u8]) -> Result<Self::Encryptions, error::Error> {
        match self {
            CryptoFormat::XOR => Ok(EncryptionRealisation::XORRealisation(XorEncryption {
                key: key.to_vec(),
            })),
            CryptoFormat::None => Err(error::Error::NoneExistEncryption),
        }
    }

    fn from_byte(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            1 => Ok(crate::realisation::encryption::CryptoFormat::XOR),
            0 => Ok(crate::realisation::encryption::CryptoFormat::None),
            _ => return Err(Self::Error::BrokenByteEncryption),
        }
    }

    fn to_byte(&self) -> u8 {
        match self {
            CryptoFormat::XOR => 1,
            CryptoFormat::None => 0,
        }
    }
}

#[derive(Debug)]

pub enum EncryptionRealisation {
    XORRealisation(XorEncryption),
}

pub enum Key {
    Xor(XorEncryption),
}

impl Encryption for EncryptionRealisation {
    type Key = Key;

    fn new(key: Self::Key) -> Self {
        match key {
            Key::Xor(k) => EncryptionRealisation::XORRealisation(k),
        }
    }

    fn decode(&self, buf: &mut [u8]) {
        match self {
            EncryptionRealisation::XORRealisation(e) => e.decode(buf),
        }
    }

    fn encode(&self, buf: &mut [u8]) {
        match self {
            EncryptionRealisation::XORRealisation(e) => e.encode(buf),
        }
    }
}
