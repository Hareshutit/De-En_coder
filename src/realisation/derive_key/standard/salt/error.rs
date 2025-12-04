#[derive(Debug)]

pub struct SaltError;

impl std::fmt::Display for SaltError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ошибка генерации соли или размера соли")
    }
}

impl core::error::Error for SaltError {}
