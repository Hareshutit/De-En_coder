#[derive(Debug)]

pub enum Error {
    ResourcePathError(Box<dyn core::error::Error + Send + Sync + 'static>),
    ReaderError(Box<dyn core::error::Error + Send + Sync + 'static>),
    WriterError(Box<dyn core::error::Error + Send + Sync + 'static>),
    BadWriteError,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResourcePathError(e) => write!(f, "Ошибка пути ресурса {}", e),
            Self::ReaderError(e) => write!(f, "Ошибка чтения по пути ресурса {}", e),
            Self::WriterError(e) => write!(f, "Ошибка записи по пути ресурса {}", e),
            Self::BadWriteError => write!(f, "Не указан путь записи "),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::ResourcePathError(e) => Some(e.as_ref()),
            Self::ReaderError(e) => Some(e.as_ref()),
            Self::WriterError(e) => Some(e.as_ref()),
            Self::BadWriteError => None,
        }
    }
}
