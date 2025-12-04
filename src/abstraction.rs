use std::fmt::Debug;

pub mod error;

/// Данный типаж абстрагирует шифрование и дешифрование данных

pub trait Encryption {
    type Key: Sized;

    fn new(key: Self::Key) -> Self;

    fn encode(&self, buf: &mut [u8]);

    fn decode(&self, buf: &mut [u8]);
}

/// Требуется, чтобы секрет можно было представить как срез байтов.

pub trait Secret<T>
where
    Self: Debug + Sized + Send + Sync + 'static,
{
    fn new(k: T) -> Self;

    /// Получить срез байтов (raw bytes) из секрета.

    fn as_bytes(&self) -> &[u8];
}

pub trait Params<P>: Debug + Send + Sync + 'static {
    /// Получить параметры в виде среза байтов,
    /// если они могут быть представлены таким образом.

    fn new(parametr: P) -> Self;

    fn as_bytes(&self) -> &[u8];
}

pub trait KeyDeriver<T, P>
where
    Self: Debug,
{
    type Error: core::error::Error + Send + Sync + 'static;

    /// Длина ключа, который генерирует KDF.

    const KEY_LENGTH: usize;

    /// Параметры, необходимые для вывода (помимо секретного ключа).
    /// Это позволяет унифицировать сигнатуру метода derive.

    type Params: Params<P> + Default;

    type Salt: SaltProvider;

    type Secret: Secret<T>;

    type Nonce: NonceProvider;

    fn new(
        secret: Self::Secret,
        _params: Self::Params,
        salt: Self::Salt,
        nonce: Self::Nonce,
    ) -> Self
    where
        Self: Sized;

    /// Основной метод для вывода криптографического ключа.
    ///
    /// # Аргументы
    /// * `secret` - Всегда есть сырой секрет (пароль или priv_key bytes)
    /// * `params` - Контекст/Публичный ключ.
    /// * `salt` - Криптографическая соль, извлеченная из заголовка файла.

    fn derive_key(&self, buffer: &mut [u8]) -> Result<(), Self::Error>
    where
        Self: Sized;
}

/// Данный типаж абстрагирует запись данных с обьекта в буфер

pub trait Reader {
    type Error: core::error::Error + Send + Sync + 'static;

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Данный типаж позволяет записывать с буфера в обьект

pub trait Writer {
    type Error: core::error::Error + Send + Sync + 'static;

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error>;
}

/// Операции для работы с обьектом

pub enum Operation {
    Open,
    Create,
    Truncate, // Открыть и очистить
}

/// Данный типаж абстрагирует путь к ресурсу

pub trait ResourcePath
where
    Self: Sized + core::fmt::Debug + Clone,
{
    type Path: core::fmt::Debug + Clone;

    type Error: core::error::Error + Send + Sync + 'static;

    fn new(path: String, op: Operation) -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn size(&self) -> usize;

    fn get_path(&self) -> &Self::Path;
}

pub trait ResourceTypeList
where
    Self: Sized + Debug + Clone + 'static,
{
    type Error: core::error::Error + Send + Sync + 'static;

    fn print_function(&self, bytes: &[u8]);

    fn to_byte(&self) -> u8;

    fn from_byte(byte: u8) -> Result<Self, Self::Error>;
}

pub trait EncryptionList
where
    Self: Sized + Debug + Clone + 'static,
{
    type Error: core::error::Error + Send + Sync + 'static;

    type Encryptions: Encryption;

    fn build(&self, key: &[u8]) -> Result<Self::Encryptions, Self::Error>;

    fn to_byte(&self) -> u8;

    fn from_byte(byte: u8) -> Result<Self, Self::Error>;
}

/// Данный типаж абстрагирует работу с обьектом по пути к ресурсу

pub trait UnifiedResourceIdentifierAbstraction: Reader + Writer + std::fmt::Debug {
    type Path: ResourcePath;

    type Type: ResourceTypeList;

    type Error: core::error::Error + Send + Sync + 'static;

    fn new(path: Self::Path, op: Operation) -> Result<Self, <Self::Path as ResourcePath>::Error>
    where
        Self: Sized;

    fn path(&mut self) -> &mut Self::Path;

    fn type_resource(&mut self) -> Result<Self::Type, <Self::Type as ResourceTypeList>::Error>;
}

pub trait NonceProvider: Sized + Debug + Clone + 'static {
    type Error: core::error::Error + Send + Sync + 'static;

    const NONCE_SIZE: usize;

    fn generate(password: &str, salt: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn as_bytes(&self) -> &[u8];

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

pub trait SaltProvider: Sized + Debug + Clone + 'static {
    type Error: core::error::Error + Send + Sync + 'static;

    const SALT_SIZE: usize;

    fn generate() -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn as_bytes(&self) -> &[u8];

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

pub trait Header
where
    Self: Sized,
{
    type Error: core::error::Error + Send + Sync + 'static;

    type Format: ResourceTypeList;

    type Cipher: EncryptionList;

    type Salt: SaltProvider;

    type Nonce: NonceProvider;

    fn new(
        format: Self::Format,
        crypto: Self::Cipher,
        salt: Self::Salt,
        nonce: Self::Nonce,
    ) -> Self;

    fn to_byte(&self) -> [u8; 42];

    fn read_from_buffer(buf: &[u8]) -> Result<Self, Self::Error>;

    fn write_to_buffer(&mut self, old_buf: &mut [u8], new_buf: &mut [u8]);

    fn remove_from_buffer(&mut self, old_buf: &mut [u8], new_buf: &mut [u8]);

    fn get_salt(&self) -> Self::Salt;

    fn get_nounce(&self) -> Self::Nonce;

    fn get_cipher(&self) -> Self::Cipher;

    fn get_format(&self) -> Self::Format;
}

pub trait Router: Reader + Writer {
    type Error: core::error::Error + Send + Sync + 'static;

    type Resource: UnifiedResourceIdentifierAbstraction;

    fn new(
        inner: <Self::Resource as UnifiedResourceIdentifierAbstraction>::Path,
        out: Option<<Self::Resource as UnifiedResourceIdentifierAbstraction>::Path>,
    ) -> Self;

    fn resource(&self) -> Result<Self::Resource, <Self as Router>::Error>;
}

pub trait Application
where
    Self: Sized,
{
    type Error: core::error::Error + Send + Sync + 'static;

    type Router: Router;

    type Scriber: Header;

    type Kdf: KeyDeriver<String, ()>;

    fn new() -> Result<Self, crate::abstraction::error::Error<Self>>;

    fn run(&mut self) -> Result<(), crate::abstraction::error::Error<Self>>;
}
