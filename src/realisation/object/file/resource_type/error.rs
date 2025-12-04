#[derive(Debug)]

pub enum Error {
    UnknowFormat,
    BrokenByteFormat,
    ReadError,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknowFormat => write!(f, "Формат файла не поддерживается"),
            Self::BrokenByteFormat => {
                write!(f, "Ошибка подписи байта формата файла магического числа")
            }
            Self::ReadError => write!(f, "Ошибка чтения файла"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::UnknowFormat => None,
            Self::BrokenByteFormat => None,
            Self::ReadError => None,
        }
    }
}
