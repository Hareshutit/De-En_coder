#[derive(Debug)]

pub enum Error {
    NotFoundSubscribe,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFoundSubscribe => write!(f, "Подпись файла не найдена"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::NotFoundSubscribe => None,
        }
    }
}
