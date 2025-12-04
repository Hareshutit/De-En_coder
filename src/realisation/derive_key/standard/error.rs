#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub enum StandardError {
    /// Ошибка возникает, если буфер или входные данные имеют неверную длину.
    LengthMismatch,
    /// Ошибка генерации случайных байт
    RandomFailed(getrandom::Error),
}

impl core::fmt::Display for StandardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StandardError::LengthMismatch => {
                write!(f, "Ошибка длины salt, key, nonce")
            }
            StandardError::RandomFailed(e) => {
                write!(f, "Ошибка генерации случайной соли: {}", e)
            }
        }
    }
}

// Преобразование ошибки getrandom в нашу кастомную ошибку
impl From<getrandom::Error> for StandardError {
    fn from(e: getrandom::Error) -> Self {
        StandardError::RandomFailed(e)
    }
}

impl core::error::Error for StandardError {}
