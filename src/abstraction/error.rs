use super::*;

/// Абстрагируют все возможные ошибки в приложении
#[derive(Debug)]

pub enum Error<A>
where
    A: Application,
{
    Application(A::Error),
    WriterError(<A::Router as Writer>::Error),
    ReaderError(<A::Router as Reader>::Error),
    RouterError(<A::Router as Router>::Error),
    ResourceAbstractionError(<<A::Router as Router>::Resource as UnifiedResourceIdentifierAbstraction>::Error),
    ResourcePathError(<<<A::Router as Router>::Resource as UnifiedResourceIdentifierAbstraction>::Path as ResourcePath>::Error),
    ResourceTypeListError(<<<A::Router as Router>::Resource as UnifiedResourceIdentifierAbstraction>::Type as ResourceTypeList>::Error),
    HeaderError(<A::Scriber as Header>::Error),
    FormatListError(<<A::Scriber as Header>::Format as ResourceTypeList>::Error),
    EncryptionListError(<<A::Scriber as Header>::Cipher as EncryptionList>::Error),
    KDFError(<A::Kdf as KeyDeriver<String, ()>>::Error),
    NonceError(<<A::Kdf as KeyDeriver<String, ()>>::Nonce as NonceProvider>::Error),
    SaltError(<<A::Kdf as KeyDeriver<String, ()>>::Salt as SaltProvider>::Error),
}

impl<A> core::fmt::Display for Error<A>
where
    A: Application,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Application(e) => write!(f, "Ошибка приложения: {}", e),
            Error::WriterError(e) => write!(f, "Ошибка записи: {}", e),
            Error::ReaderError(e) => write!(f, "Ошибка чтения: {}", e),
            Error::ResourcePathError(e) => write!(f, "Ошибка пути к ресурсу: {}", e),
            Error::ResourceAbstractionError(e) => write!(f, "Ошибка ресурса: {}", e),
            Error::ResourceTypeListError(e) => write!(f, "Ошибка типа ресурса: {}", e),
            Error::EncryptionListError(e) => write!(f, "Ошибка шифрования: {}", e),
            Error::RouterError(e) => write!(f, "Ошибка роутирования: {}", e),
            Error::FormatListError(e) => write!(f, "Ошибка поддерживаемых форматов: {}", e),
            Error::HeaderError(e) => write!(f, "Ошибка подписи файла: {}", e),
            Error::KDFError(e) => write!(f, "Ошибка генерации деривации ключа: {}", e),
            Error::NonceError(e) => write!(f, "Ошибка генерации уникального числа: {}", e),
            Error::SaltError(e) => write!(f, "Ошибка генерации соли: {}", e),
        }
    }
}

impl<A> core::error::Error for Error<A>
where
    A: Application + core::fmt::Debug,
    A::Router: UnifiedResourceIdentifierAbstraction + core::fmt::Debug,
    A::Scriber: Header + core::fmt::Debug,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Error::Application(e) => Some(e),
            Error::WriterError(e) => Some(e),
            Error::ReaderError(e) => Some(e),
            Error::ResourcePathError(e) => Some(e),
            Error::ResourceAbstractionError(e) => Some(e),
            Error::ResourceTypeListError(e) => Some(e),
            Error::EncryptionListError(e) => Some(e),
            Error::RouterError(e) => Some(e),
            Error::FormatListError(e) => Some(e),
            Error::HeaderError(e) => Some(e),
            Error::KDFError(e) => Some(e),
            Error::NonceError(e) => Some(e),
            Error::SaltError(e) => Some(e),
        }
    }
}
