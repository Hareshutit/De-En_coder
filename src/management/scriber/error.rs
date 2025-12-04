#[derive(Debug)]

pub enum Error<RT, CA, SP, NP>
where
    RT: crate::abstraction::ResourceTypeList,
    CA: crate::abstraction::EncryptionList,
    SP: crate::abstraction::SaltProvider,
    NP: crate::abstraction::NonceProvider,
{
    NotFoundSubscribe,
    ExcessError,
    FormatError(RT::Error),
    CipherError(CA::Error),
    SaltError(SP::Error),
    NonceError(NP::Error),
}

impl<RT, CA, SP, NP> core::fmt::Display for Error<RT, CA, SP, NP>
where
    RT: crate::abstraction::ResourceTypeList,
    CA: crate::abstraction::EncryptionList,
    SP: crate::abstraction::SaltProvider,
    NP: crate::abstraction::NonceProvider,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFoundSubscribe => write!(f, "Подпись файла не найдена"),
            Self::FormatError(e) => write!(f, "Неправильно указан формат данных {}", e),
            Self::CipherError(e) => {
                write!(f, "Неправильно указан формат шифрования {}", e)
            }
            Self::SaltError(e) => write!(f, "Ошибка соли {}", e),
            Self::NonceError(e) => write!(f, "Ошибка вектора инициализации {}", e),
            Self::ExcessError => write!(f, "Не соответствие размера протокола"),
        }
    }
}

impl<RT, CA, SP, NP> core::error::Error for Error<RT, CA, SP, NP>
where
    RT: crate::abstraction::ResourceTypeList,
    CA: crate::abstraction::EncryptionList,
    SP: crate::abstraction::SaltProvider,
    NP: crate::abstraction::NonceProvider,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::NotFoundSubscribe => None,
            Self::FormatError(e) => Some(e),
            Self::CipherError(e) => Some(e),
            Self::SaltError(e) => Some(e),
            Self::NonceError(e) => Some(e),
            Self::ExcessError => None,
        }
    }
}
