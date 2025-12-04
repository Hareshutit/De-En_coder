#[derive(Debug)]
pub enum Error {
    NoneExistEncryption,
    BrokenByteEncryption,
    IncorectDataEncryption,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoneExistEncryption => write!(f, "Данного шифратора несуществует"),
            Self::BrokenByteEncryption => {
                write!(f, "Ошибка подписи байта шифровщика магического числа")
            }
            Self::IncorectDataEncryption => {
                write!(f, "Ошибка данные необходимые шифратору неверные")
            }
        }
    }
}
impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::NoneExistEncryption => None,
            Self::BrokenByteEncryption => None,
            Self::IncorectDataEncryption => None,
        }
    }
}