use crate::abstraction::Application;

pub mod abstraction {
    use std::fmt::Debug;

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
            Self: Debug
    {
        type Error: core::error::Error + Send + Sync + 'static;

        /// Длина ключа, который генерирует KDF.
        const KEY_LENGTH: usize;

        /// Параметры, необходимые для вывода (помимо секретного ключа).
        /// Это позволяет унифицировать сигнатуру метода derive.
        type Params: Params<P> + Default;
        type Salt: SaltProvider;
        type Secret:  Secret<T>;
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
        fn derive_key(
            &self,
            buffer: &mut [u8],
        ) -> Result<(), Self::Error>
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

        fn new(
            path: String, 
            op: Operation
        ) -> Result<Self, Self::Error>
        where
            Self: Sized;
            
        fn size(&self) -> usize;
        fn get_path(&self) -> &Self::Path;
    }

    pub trait ResourceTypeList
        where
            Self:Sized+Debug + Clone + 'static,
    {
        type Error: core::error::Error + Send + Sync + 'static;

        fn print_function(&self, bytes: &[u8]);
        fn to_byte(&self) -> u8;
        fn from_byte(byte: u8) -> Result<Self, Self::Error>;
    }
    
    pub trait EncryptionList 
        where
            Self: Sized+Debug+ Clone +'static,
    {        
        type Error: core::error::Error + Send + Sync + 'static;
        type Encryptions: Encryption;
        
        fn build(&self, key: &[u8]) -> Result<Self::Encryptions, Self::Error>;
        fn to_byte(&self) -> u8;
        fn from_byte(byte: u8) ->  Result<Self, Self::Error>;
    }

    /// Данный типаж абстрагирует работу с обьектом по пути к ресурсу
    pub trait UnifiedResourceIdentifierAbstraction: Reader + Writer + std::fmt::Debug {
        type Path: ResourcePath;
        type Type: ResourceTypeList;
        type Error: core::error::Error + Send + Sync + 'static;

        fn new(
            path: Self::Path,
            op: Operation,
        ) -> Result<Self, <Self::Path as ResourcePath>::Error>
            where
                Self: Sized;
        fn path(&mut self) -> &mut Self::Path;
        fn type_resource(&mut self) -> Result<Self::Type, <Self::Type as ResourceTypeList>::Error>;
    }


    
    pub trait NonceProvider:  Sized+Debug+Clone + 'static {
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

    pub trait SaltProvider:  Sized+Debug+Clone + 'static {
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
            Self: Sized
    {
        type Error: core::error::Error + Send + Sync + 'static;
        type Format: ResourceTypeList;
        type Cipher: EncryptionList;
        type Salt: SaltProvider;
        type Nonce: NonceProvider;

        fn new(format: Self::Format, crypto: Self::Cipher, salt: Self::Salt, nonce: Self::Nonce) -> Self;
        fn to_byte(&self) -> [u8; 42];
        fn read_from_buffer(buf: &[u8]) -> Result<Self, Self::Error>;
        fn write_to_buffer(&mut self, old_buf: &mut [u8], new_buf: &mut [u8]);
        fn remove_from_buffer(&mut self, old_buf: &mut [u8], new_buf: &mut [u8]);
        fn get_salt(&self) -> Self::Salt;
        fn get_nounce(&self) -> Self::Nonce;
        fn get_cipher(&self) -> Self::Cipher;
        fn get_format(&self) -> Self::Format;
    }

    pub trait Router:  Reader + Writer {
        type Error: core::error::Error + Send + Sync + 'static;
        type Resource: UnifiedResourceIdentifierAbstraction;
        
        fn new(inner: <Self::Resource as UnifiedResourceIdentifierAbstraction>::Path, out: Option<<Self::Resource as UnifiedResourceIdentifierAbstraction>::Path>) -> Self;
        fn resource(&self) -> Result<Self::Resource, <Self as Router>::Error>;
    }

    pub trait Application
        where
            Self: Sized
    {
        type Error: core::error::Error + Send + Sync + 'static;
        type Router: Router;
        type Scriber: Header;
        type Kdf: KeyDeriver<String, ()>;

        fn new() -> Result<Self,  crate::abstraction::error::Error<Self>>;

        fn run(
            &mut self, 
        ) -> Result<(), crate::abstraction::error::Error<Self>>;

        
    }

    pub mod error {

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
                    Error::NonceError(e)  => write!(f, "Ошибка генерации уникального числа: {}", e),
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
                    Error::SaltError(e)  => Some(e),
                }
            }
        }


    }


}

pub mod realisation {

    pub mod derive_key {

        pub mod chacha {
            use crate::abstraction::{Secret, SaltProvider};

            pub mod secret {
                /// Секрет (ключ) для ChaCha20. Должен быть 32 байта.
                #[derive(Debug)]
                pub struct ChaChaKey(pub Vec<u8>);
                impl crate::abstraction::Secret<String> for ChaChaKey {
                    fn as_bytes(&self) -> &[u8] { &self.0 }
                    fn new(k: String) -> Self {
                        ChaChaKey(k.into_bytes())
                    }
                }
            }

            pub mod nonce {
                #[derive(Debug, Clone)]
                pub struct ChaChaNonce(pub [u8; 12]);

                impl crate::abstraction::NonceProvider for ChaChaNonce {
                    type Error = super::error::ChaChaError;
                    const NONCE_SIZE: usize = 12;

                    fn generate(password: &str, salt: &[u8]) -> Result<Self, Self::Error>
                    where
                        Self: Sized,
                    {
                        use sha2::{Digest, Sha256};
                        let mut hasher = Sha256::new();
                        hasher.update(password.as_bytes());
                        hasher.update(salt);
                        let digest = hasher.finalize(); // 32 байта

                        let mut nonce = [0u8; 12];
                        nonce.copy_from_slice(&digest[..12]);
                        Ok(ChaChaNonce(nonce))
                    }

                    fn as_bytes(&self) -> &[u8] {
                        &self.0
                    }

                    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>
                    where
                        Self: Sized,
                    {
                        let mut arr = [0u8; Self::NONCE_SIZE];
                        arr.copy_from_slice(bytes);
                        Ok(Self(arr))
                    }
                }
            }

            pub mod salt {
       
                const STANDARD_SALT_SIZE: usize = 16;
        
                #[derive(Debug, Clone)]
                pub struct StandardSalt {
                    value: [u8; STANDARD_SALT_SIZE],
                }
        
        
                impl crate::abstraction::SaltProvider for StandardSalt {
                    type Error = error::SaltError;
                    const SALT_SIZE: usize = STANDARD_SALT_SIZE;
        
                    fn generate() -> Result<Self, Self::Error> {
                        let mut salt = [0u8; Self::SALT_SIZE];
                        getrandom::fill(&mut salt).map_err(crate::realisation::derive_key::chacha::error::ChaChaError::RandomFailed).map_err(|e| error::SaltError)?;
                        Ok(StandardSalt{value: salt})
                    }

                    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
                        if bytes.len() != Self::SALT_SIZE {
                            return Err(error::SaltError);
                        }
                        let mut value = [0u8; Self::SALT_SIZE];
        
                        value.copy_from_slice(bytes); 
                        Ok(Self{value})
                    }

                    fn as_bytes(&self) -> &[u8] {
                        &self.value
                    }
                }
        
                pub mod error {
                    
                #[derive(Debug)]
                    pub struct SaltError; 
                    impl std::fmt::Display for SaltError {
                        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                            write!(f, "Ошибка генерации соли или размера соли")
                        }
                    }
                    impl core::error::Error for SaltError {}
                }
            }

            pub mod parametr {
                impl crate::abstraction::Params<()> for () {
                    fn new(parametr: ()) -> Self {
                        parametr
                    }
                    fn as_bytes(&self) -> &[u8] { &[] }
                }
            }

            #[derive(Debug)]
            pub struct ChaChaKdf<const L: usize> {
                params: (),
                salt: salt::StandardSalt,
                secret: secret::ChaChaKey,
                nonce: nonce::ChaChaNonce,
            }

            impl<const L: usize> crate::abstraction::KeyDeriver<String, ()> for ChaChaKdf<L> {
                type Error = error::ChaChaError;
                const KEY_LENGTH: usize = L;

                /// Мы не используем параметры в данном генераторе, поэтому указываем `()`.
                type Params = ();
                
                type Salt = salt::StandardSalt;

                type Secret = secret::ChaChaKey;

                type Nonce =  nonce::ChaChaNonce;

                fn new(
                    secret: Self::Secret,
                    _params: Self::Params, // Игнорируем параметры
                    salt: Self::Salt,
                    nonce: Self::Nonce,
                ) -> Self
                    where
                        Self: Sized,
                {
                    ChaChaKdf::<L> {
                        salt: salt,
                        secret: secret,
                        params: (),
                        nonce: nonce,

                    }
                }

                /// Генерирует гамму (keystream) в `buffer`.
                fn derive_key(
                    &self,
                    buffer: &mut [u8],
                ) -> Result<(), Self::Error>
                where
                    Self: Sized,
                {
                    // Проверяем длину буфера
                    if buffer.len() != Self::KEY_LENGTH {
                        return Err(Self::Error::LengthMismatch);
                    }

                    // 1) Построим SHA256(secret and salt)
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(self.secret.as_bytes());
                    hasher.update(self.salt.as_bytes());
                    let digest = hasher.finalize(); // 32 байта

                    // 2) Если KEY_LENGTH <= 32, используем первые KEY_LENGTH байт digest
                    //    Если больше, можно расширять при помощи HKDF/DRBG — здесь
                    //    мы поддерживаем KEY_LENGTH <= 32 (рекомендация: 32)
                    if Self::KEY_LENGTH > 32 {
                        // для простоты — не поддерживаем >32 в этой реализации
                        return Err(Self::Error::LengthMismatch);
                    }

                    buffer.copy_from_slice(&digest[..Self::KEY_LENGTH]);

                    Ok(())
                }
            }

            pub mod error {
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub enum ChaChaError {
                /// Ошибка возникает, если буфер или входные данные имеют неверную длину.
                LengthMismatch,
                /// Ошибка генерации случайных байт
                RandomFailed(getrandom::Error),
            }

            impl core::fmt::Display for ChaChaError {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    match self {
                        ChaChaError::LengthMismatch => write!(f, "Ошибка длины salt, key, nonce"),
                        ChaChaError::RandomFailed(e) => write!(f, "Ошибка генерации случайной соли: {}", e),
                    }
                }
            }

            // Преобразование ошибки getrandom в нашу кастомную ошибку
            impl From<getrandom::Error> for ChaChaError {
                fn from(e: getrandom::Error) -> Self {
                    ChaChaError::RandomFailed(e)
                }
            }

            impl core::error::Error for ChaChaError {}
        }
        }


        
    }

    pub mod encryption {
        use crate::{abstraction::Encryption, realisation::encryption::{xor::XorEncryption}};

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
                    CryptoFormat::XOR => Ok(EncryptionRealisation::XORRealisation(XorEncryption{key: key.to_vec()})),
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

        pub mod error {
            #[derive(Debug)]
            pub enum Error {
                NoneExistEncryption,
                BrokenByteEncryption,
                IncorectDataEncryption,
            }

            impl core::fmt::Display for Error
            {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
                    match self {
                        Self::NoneExistEncryption => write!(f, "Данного шифратора несуществует"),
                        Self::BrokenByteEncryption => write!(f, "Ошибка подписи байта шифровщика магического числа"),
                        Self::IncorectDataEncryption => write!(f, "Ошибка данные необходимые шифратору неверные"),
                    }
                }
            }

            impl core::error::Error for Error
            {
                fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
                    match self {
                        Self::NoneExistEncryption => None,
                        Self::BrokenByteEncryption => None,
                        Self::IncorectDataEncryption => None,
                    }
                }
            }

        }

        pub mod xor {
            use crate::abstraction::Encryption;
            #[derive(Debug)]
            pub struct XorEncryption {
                pub key: Vec<u8>,
            }

            impl Encryption for XorEncryption {
                type Key = Vec<u8>;

                fn new(key: Self::Key) -> Self {
                    Self { key }
                }
                fn encode(&self, buf: &mut [u8]) {
                    let key_len = self.key.len();
                    if key_len == 0 { return; } 


                    for (i, byte) in buf.iter_mut().enumerate() {
                        let key_byte = self.key[i % key_len];
                        *byte ^= key_byte;
                    }
                }

                fn decode(&self, buf: &mut [u8]) {
                    let key_len = self.key.len();
                    if key_len == 0 { return; }

                    for (i, byte) in buf.iter_mut().enumerate() {
                        let key_byte = self.key[i % key_len];
                        *byte ^= key_byte;
                    }
                }
            }

            
        }
    }



    pub mod object {
        pub mod file {
            use std::io::{Read, Write};

            use crate::abstraction::ResourcePath;

            pub mod path {
                pub mod file_system {

                    #[derive(Debug, Clone)]
                    pub struct FilePath(std::path::PathBuf);

                    impl crate::abstraction::ResourcePath for FilePath {
                        type Path = std::path::PathBuf;
                        type Error = std::io::Error;

                        fn new(
                            path: String,
                            op: crate::abstraction::Operation,
                        ) -> Result<Self, Self::Error>
                        where
                            Self: Sized,
                        {
                            let path = std::path::PathBuf::from(path);
                            match std::fs::metadata(&path) {
                                Ok(metadata) => {
                                    if metadata.is_file() {
                                        Ok(FilePath(path))
                                    } else {
                                        Err(std::io::Error::new(
                                            std::io::ErrorKind::InvalidInput,
                                            format!(
                                                "Путь '{}' не ведет к файлу, ожидался файл",
                                                path.display()
                                            ),
                                        ))
                                    }
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                    match op {
                                        crate::abstraction::Operation::Open
                                        | crate::abstraction::Operation::Truncate => {
                                            Err(std::io::Error::new(
                                                std::io::ErrorKind::NotFound,
                                                format!(
                                                    "Файла по пути, '{}' не существует",
                                                    path.display()
                                                ),
                                            ))
                                        }
                                        crate::abstraction::Operation::Create => Ok(FilePath(path)),
                                    }
                                }
                                Err(e) => {
                                    Err(std::io::Error::new(
                                        e.kind(),
                                        format!(
                                            "Ошибка при проверке пути '{}': {}",
                                            path.display(),
                                            e
                                        ),
                                    ))
                                }
                            }
                        }

                        fn size(&self) -> usize {
                            match std::fs::metadata(&self.0) {
                                Ok(metadata) => metadata.len() as usize,
                                Err(_) => 0,
                            }
                        }

                        fn get_path(&self) -> &Self::Path {
                            &self.0
                        }

                    }
                }
            }

            pub mod resource_type {
                pub mod common {
                    use docx_rs::{ DocumentChild, ParagraphChild, RunChild};
                   
                    /// Рекурсивно извлекает текст из документа
                    pub fn extract_text_from_docx(docx: &docx_rs::Docx) -> String {
                        let mut result = String::new();
                        for element in &docx.document.children {
                            match element {
                                DocumentChild::Paragraph(p) => {
                                    result.push_str(&extract_text_from_paragraph(p));
                                    result.push('\n');
                                }
                                DocumentChild::Table(t) => {
                                    for row in &t.rows {
                                        if let docx_rs::TableChild::TableRow(row) = row { 
                                            // Теперь 'row' - это TableRow, и ячейки лежат в row.cells
                                            for cell in &row.cells { 
                                                if let docx_rs::TableRowChild::TableCell(cell) = cell { 
                                                    for content in &cell.children {
                                                        // Внутри ячейки таблицы
                                                        if let docx_rs::TableCellContent::Paragraph(p) = content {
                                                            result.push_str(&extract_text_from_paragraph(p));
                                                            result.push(' ');
                                                        }
                                                    }
                                                }
                                            }
                                            result.push('\n'); // Новая строка после каждой строки таблицы
                                        }   
                                    }
                                }
                                _ => {} 
                            }
                        }
                        result
                    }

                    /// Извлекает текст из конкретного параграфа
                    pub fn extract_text_from_paragraph(p: &docx_rs::Paragraph) -> String {
                        let mut text = String::new();
                        for child in &p.children {
                            if let ParagraphChild::Run(run) = child {
                                for run_child in &run.children {
                                    if let RunChild::Text(t) = run_child {
                                        text.push_str(&t.text);
                                    }
                                }
                            }
                        }
                        text
                    }
                }


                #[derive(Debug, Clone)]
                pub enum ResourceType{
                    FileFormat(file_format::FileFormat),
                    Crypted,
                    UnknowFormat,
                }

                impl crate::abstraction::ResourceTypeList for ResourceType {
                    type Error = error::Error;

                    fn print_function(&self, bytes: &[u8]) {
                        match self {
                            Self::FileFormat(f) => {
                                match f {
                                    file_format::FileFormat::PlainText => {
                                        let text: std::borrow::Cow<str> = String::from_utf8_lossy(bytes);
                                        println!("--- Дешифрованный ТЕКСТ (TXT) ---");
                                        println!("{}", text);
                                        println!("----------------------------------");
                                    },
                                    file_format::FileFormat::OfficeOpenXmlDocument =>  {
                                        println!("--- Дешифрованный DOCX ---");
                                        // Используем docx-rs для чтения из байтов
                                        match docx_rs::read_docx(bytes) {
                                            Ok(docx) => {
                                                let text = common::extract_text_from_docx(&docx);
                                                println!("{}", text);
                                            },
                                            Err(e) => {
                                                println!("Ошибка парсинга DOCX файла: {:?}", e);
                                            }
                                        }
                                        println!("----------------------------");
                                    },
                                    _ => {
                                        println!("--- Дешифрованные БИНАРНЫЕ ДАННЫЕ (Формат: {:?}) ---", f);
                                        let slice_len = std::cmp::min(bytes.len(), 128);
                                        println!("Первые {} байт: {:?}", slice_len, &bytes[..slice_len]);
                                        println!("--------------------------------------------------");
                                    },
                                }
                            },   
                            _ => {
                                println!("--- Дешифрованные БИНАРНЫЕ ДАННЫЕ (Неизвестный тип) ---");
                                let slice_len = std::cmp::min(bytes.len(), 128);
                                println!("Первые {} байт: {:?}", slice_len, &bytes[..slice_len]);
                                println!("--------------------------------------------------");
                            }
                        }
                    }


                    fn to_byte(&self) -> u8  {
                        match self {
                            ResourceType::FileFormat(file_format::FileFormat::OfficeOpenXmlDocument) => 3,
                            ResourceType::FileFormat(file_format::FileFormat::PlainText) => 2,
                            ResourceType::Crypted => 1,
                            _ => 0,
                        }
                    }

                    fn from_byte(byte: u8) -> Result<Self, Self::Error> {
                        match byte {
                            3 =>  Ok(ResourceType::FileFormat(file_format::FileFormat::OfficeOpenXmlDocument)),
                            2 =>  Ok( ResourceType::FileFormat(file_format::FileFormat::PlainText)),
                            1 =>  Ok(ResourceType::Crypted),
                            0 =>  Ok(ResourceType::UnknowFormat),
                            _ => Err(Self::Error::BrokenByteFormat),
                        }
                        
                    }
                }

                pub mod error{
                    #[derive(Debug)]
                    pub enum Error{
                        UnknowFormat,
                        BrokenByteFormat,
                        ReadError,
                    }

                    impl core::fmt::Display for Error
                    {
                        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
                            match self {
                                Self::UnknowFormat => write!(f, "Формат файла не поддерживается"),
                                Self::BrokenByteFormat => write!(f, "Ошибка подписи байта формата файла магического числа"),
                                Self::ReadError => write!(f, "Ошибка чтения файла"),
                            }
                        }
                    }

                    impl core::error::Error for Error
                    {
                        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
                            match self {
                                Self::UnknowFormat => None,
                                Self::BrokenByteFormat => None,
                                Self::ReadError => None,
                            }
                        }
                    }
                }
                
    
            }


            #[derive(Debug)]
            pub struct FileResourceIdentifier {
                file: std::fs::File,
                path: path::file_system::FilePath,
            }

            impl crate::abstraction::Reader for FileResourceIdentifier {
                type Error = std::io::Error;

                fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
                    self.file.read_exact(buf)?;
                    Ok(buf.len())
                }
            }

            impl crate::abstraction::Writer for FileResourceIdentifier {
                type Error = std::io::Error;

                fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
                    self.file.write_all(buf)?;
                    Ok(buf.len())
                }
            }

            impl crate::abstraction::UnifiedResourceIdentifierAbstraction for FileResourceIdentifier {
                type Path = path::file_system::FilePath;
                type Type = resource_type::ResourceType;
                type Error = std::io::Error;

                fn new(
                    path: Self::Path,
                    op: crate::abstraction::Operation,
                ) -> Result<Self, <Self::Path as crate::abstraction::ResourcePath>::Error>
                where
                    Self: Sized,
                {
                    match op {
                        crate::abstraction::Operation::Open => {
                            let file = std::fs::File::open(&path.get_path())?;
                            Ok(FileResourceIdentifier { file, path: path })
                        }
                        crate::abstraction::Operation::Create => {
                            let file = std::fs::File::create(&path.get_path())?;
                            Ok(FileResourceIdentifier { file, path: path })
                        }
                        crate::abstraction::Operation::Truncate => {
                            let file = std::fs::OpenOptions::new()
                                .write(true)
                                .truncate(true)
                                .open(&path.get_path())?;
                            Ok(FileResourceIdentifier { file, path: path })
                        }
                    }
                }

                fn path(&mut self) -> &mut Self::Path {
                    &mut self.path
                }

                fn type_resource(&mut self) -> Result<Self::Type, <Self::Type as crate::abstraction::ResourceTypeList>::Error> {
                    match file_format::FileFormat::from_reader(&mut self.file) {
                        Ok(r) => Ok(Self::Type::FileFormat(r)),
                        Err(e) => Err(crate::realisation::object::file::resource_type::error::Error::ReadError),
                    }
                }
            }
        }
    }
}

pub mod management {
    use std::marker::PhantomData;

    use clap::Parser;
    use crate::{abstraction::{ EncryptionList, ResourcePath, UnifiedResourceIdentifierAbstraction}, realisation::encryption::CryptoFormat};
    use crate::abstraction::Secret;
    use crate::abstraction::Encryption;

    pub mod scriber {

        /// Записывается в начало шифрованного файла  42 байта.
        /// 
        /// Уникальная метка для индентификации файла,	6 байт.
        /// Версия формата файла,	1 байт.
        /// Алгоритм шифрования, 1 байт.
        /// Исходный формат файла, 1 байт.
        /// Зарезервированные байты, 5 байт.
        /// Случайная соль, 16 байт.
        /// Вектор Инициализации, 12 байт.
        #[derive(Debug)]
        pub struct  Scriber<RT, CA, SP, NP>
            where 
                RT: crate::abstraction::ResourceTypeList,
                CA: crate::abstraction::EncryptionList,
                SP: crate::abstraction::SaltProvider,
                NP: crate::abstraction::NonceProvider, 
        {
            format: RT,
            cipher: CA,
            version: u8,
            salt: SP,
            nonce: NP,
        }

        impl<RT, CA, SP, NP> crate::abstraction::Header for Scriber<RT, CA, SP, NP>
            where 
                RT: crate::abstraction::ResourceTypeList,
                CA: crate::abstraction::EncryptionList,
                SP: crate::abstraction::SaltProvider,
                NP: crate::abstraction::NonceProvider, 
        {
            type Error = error::Error<RT, CA, SP, NP>;
            type Cipher = CA;
            type Format = RT;
            type Salt = SP;
            type Nonce = NP;

            fn new(format: Self::Format,cipher: Self::Cipher, salt: Self::Salt, nonce: Self::Nonce) -> Self {
                Self {format,cipher, version: 1, salt: salt, nonce: nonce}
            }

            fn to_byte(&self) -> [u8; 42] {
                let mut buf = [0u8; 42];
                let mut offset = 0;

                buf[offset..offset + 6].copy_from_slice(b"CRYPTO");
                offset += 6;

                buf[offset] = self.version;
                offset += 1;

                buf[offset] = self.cipher.to_byte();
                offset += 1;

                buf[offset] = self.format.to_byte();
                offset += 1;

                offset += 5;

                buf[offset..offset + 16].copy_from_slice(self.salt.as_bytes());
                offset += 16;

                buf[offset..offset + 12].copy_from_slice(&self.nonce.as_bytes());
                offset += 12;

                buf
            }

            fn read_from_buffer(buf: &[u8]) -> Result<Self, Self::Error> {
                const HEADER_SIZE: usize = 42;
                const MAGIC_BYTES: &[u8] = b"CRYPTO";
                
                if buf.len() < HEADER_SIZE {
                    return Err(Self::Error::ExcessError); 
                }

                let mut offset = 0;

                if buf[offset..offset + MAGIC_BYTES.len()] != *MAGIC_BYTES {
                    return Err(Self::Error::NotFoundSubscribe); 
                }
                offset += MAGIC_BYTES.len();

                let version = buf[offset];
                offset += 1;
                
                let cipher = Self::Cipher::from_byte(buf[offset])
                    .map_err(|e| Self::Error::CipherError(e) )?;
                offset += 1; 

                let format = Self::Format::from_byte(buf[offset])
                    .map_err(|e| Self::Error::FormatError(e) )?;
                offset += 1; 

 
                offset += 5; 


                let salt_slice = &buf[offset..offset + SP::SALT_SIZE];
                let salt = SP::from_bytes(salt_slice)
                    .map_err(|e| Self::Error::SaltError(e.into()))?; 
                offset += SP::SALT_SIZE; 


                let nonce_slice = &buf[offset..offset + NP::NONCE_SIZE];
                let nonce = NP::from_bytes(nonce_slice)
                    .map_err(|e| Self::Error::NonceError(e.into()))?; 


                Ok(Self {
                    version: version,
                    cipher: cipher,
                    format: format,
                    salt: salt,
                    nonce: nonce, 
                })
            }

            fn write_to_buffer(&mut self, old_buf: &mut [u8], new_buf: &mut [u8]) {
            // 1. Проверка размера буфера new_buf (критический шаг)
                let required_len = 42 + old_buf.len();
                // if new_buf.len() < required_len {
                //     return Err("Размер выходного буфера 'new_buf' недостаточен для Заголовка и Данных.");
                // }
                
                // 2. Получаем байты заголовка (эффективнее, чем to_vec() внутри)
                let header_bytes = self.to_byte(); 
                
                // 3. Копируем заголовок в начало new_buf
                new_buf[..42].copy_from_slice(&header_bytes);
                
                // 4. Копируем данные после заголовка
                new_buf[42..required_len].copy_from_slice(old_buf);
                
                // Обнуляем лишние байты, если new_buf был больше required_len
                // (Хотя лучше, чтобы new_buf был точно required_len)
                
                // Ok(())
            }

            fn remove_from_buffer(&mut self, old_buf: &mut [u8], new_buf: &mut [u8]) {
            // 1. Проверка минимального размера
                // if old_buf.len() < HEADER_SIZE {
                //     return Err("Входной буфер слишком мал, чтобы содержать заголовок.");
                // }
                
                // 2. Проверка размера выходного буфера
                let data_len = old_buf.len() - 42;
                // if new_buf.len() < data_len {
                //     return Err("Размер выходного буфера 'new_buf' недостаточен для данных.");
                // }

                // 3. Пропускаем заголовок и копируем только данные
                new_buf[..data_len].copy_from_slice(&old_buf[42..]);
                
                // Ok(()) 
            }

            fn get_format(&self) -> Self::Format {
                self.format.clone()
            }
            
            fn get_nounce(&self) -> Self::Nonce {
                self.nonce.clone()
            }
            
            fn get_salt(&self) -> Self::Salt {
                self.salt.clone()
            }

            fn get_cipher(&self) -> Self::Cipher {
                self.cipher.clone()
            }

        }

        pub mod error {
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
                        Self::CipherError(e) => write!(f, "Неправильно указан формат шифрования {}", e),
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
        }
    }

    pub mod interface {

        pub mod cli {
            #[derive(clap::Parser, Debug)]
            pub struct Cli {
                #[command(subcommand)]
                pub command: Command,
            }

            #[derive(clap::Subcommand, Debug)]
            pub enum Command {
                ///Шифрование файла, аргумент - путь до файла
                Prepare {
                    path_inner: String,
                    #[arg(long)]
                    path_outer: Option<String>,
                    #[arg(long, default_value_t = String::from(""))]
                    password: String,
                    #[arg(long, default_value_t = crate::realisation::encryption::CryptoFormat::XOR)]
                    cipher: crate::realisation::encryption::CryptoFormat,
                },
                ///Чтение файла, аргумент - путь до файла
                Read { 
                    path: String,
                    #[arg(long, default_value_t = String::from(""))]
                    password: String,
                },
                ///Расшифровка файла, аргумент - путь до файла
                Decrypt {
                    path_inner: String,
                    #[arg(long)]
                    path_outer: Option<String>,
                    #[arg(long, default_value_t = String::from(""))]
                    password: String,
                },
            }
        }
    }
    
    pub mod router {
        #[derive(Debug)]
        pub struct Router<U>
            where 
                U: crate::abstraction::UnifiedResourceIdentifierAbstraction,
                U::Path: crate::abstraction::ResourcePath,
        {
            inner: U::Path,
            out: Option<U::Path>,
        }

        impl<U> crate::abstraction::Router for Router<U>
        where 
            U: crate::abstraction::UnifiedResourceIdentifierAbstraction,
            U::Path : crate::abstraction::ResourcePath
        {
            type Error = error::Error;
            type Resource = U;
            
            fn new(inner: U::Path, out: Option<U::Path>) -> Self {
                Router { inner, out }
            }

            fn resource(&self) -> Result<Self::Resource, <Self as crate::abstraction::Router>::Error> {
                U::new(self.inner.clone(), crate::abstraction::Operation::Open).map_err(|e| error::Error::ResourcePathError(Box::new(e)))
            }
        }


        impl<U> crate::abstraction::Writer for Router<U>
            where 
               U: crate::abstraction::UnifiedResourceIdentifierAbstraction,
               U::Path: crate::abstraction::ResourcePath
        {
            type Error = error::Error;
            
            fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
                let out = match self.out {
                    Some(ref out) => out,
                    None => return Err(Self::Error::BadWriteError),
                };

                let mut resource = U::new(out.clone(), crate::abstraction::Operation::Create)
                    .map_err(|e| Self::Error::ResourcePathError(Box::new(e)))?;

                resource.write(buf).map_err(|e| Self::Error::WriterError(Box::new(e)))
            }
        }

        impl<U> crate::abstraction::Reader for Router<U>
            where 
                U: crate::abstraction::UnifiedResourceIdentifierAbstraction,
                U::Path: crate::abstraction::ResourcePath
        {
            type Error = error::Error;
            
            fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
                let mut inr = U::new(self.inner.clone(), crate::abstraction::Operation::Open).map_err(|e| Self::Error::ResourcePathError(Box::new(e)))?;

                inr.read(buf).map_err(|e| Self::Error::ReaderError(Box::new(e)))
            }
        }

        pub mod error {
            #[derive(Debug)]
            pub enum Error
            {
                ResourcePathError(Box<dyn core::error::Error + Send + Sync + 'static>),
                ReaderError(Box<dyn core::error::Error + Send + Sync + 'static>),
                WriterError(Box<dyn core::error::Error + Send + Sync + 'static>),
                BadWriteError,
            }

            impl core::fmt::Display for Error
            {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
                    match self {
                        Self::ResourcePathError(e) => write!(f, "Ошибка пути ресурса {}", e),
                        Self::ReaderError(e) => write!(f, "Ошибка чтения по пути ресурса {}", e),
                        Self::WriterError(e) => write!(f, "Ошибка записи по пути ресурса {}", e),
                        Self::BadWriteError => write!(f, "Не указан путь записи "),
                    }
                }
            }

            impl core::error::Error for Error
            {
                fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
                    match self {
                        Self::ResourcePathError(e) => Some(e.as_ref()),
                        Self::ReaderError(e) => Some(e.as_ref()),
                        Self::WriterError(e) => Some(e.as_ref()),
                        Self::BadWriteError => None,
                    }
                }
            }
        }
    }

    pub mod error{
        #[derive(Debug)]
        pub enum Error{
            NotFoundSubscribe,
        }

        impl core::fmt::Display for Error
        {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::NotFoundSubscribe => write!(f, "Подпись файла не найдена"),
                }
            }
        }

        impl core::error::Error for Error
        {
            fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
                match self {
                    Self::NotFoundSubscribe => None,
                }
            }
        }
    }
    
    #[derive(Debug)]    
    pub struct App<R, M, K, F, S, N>
        where 
            R: crate::abstraction::Router,
            M: crate::abstraction::Header,
            K: crate::abstraction::KeyDeriver<String, ()>,
            F: crate::abstraction::ResourceTypeList,
            S: crate::abstraction::SaltProvider,
            N: crate::abstraction::NonceProvider,

    {
        buffer: Vec<u8>,
        resource: R,
        scriber: M,
        key_deriver: K,
        cli: interface::cli::Cli,

        _marker_f: std::marker::PhantomData<F>,
        _marker_s: std::marker::PhantomData<S>,
        _marker_n: std::marker::PhantomData<N>,
    }

    impl<R, M, K, F, S, N> crate::abstraction::Application for  App<R, M, K, F, S, N>
        where
            F: crate::abstraction::ResourceTypeList,
            R: crate::abstraction::Router<Resource: crate::abstraction::UnifiedResourceIdentifierAbstraction<Type=F>>,
            M: crate::abstraction::Header<Format=F, Nonce = N, Salt = S, Cipher = CryptoFormat>,
            S: crate::abstraction::SaltProvider,
            N: crate::abstraction::NonceProvider,
            K: crate::abstraction::KeyDeriver<String, (), Salt = S, Nonce = N>,
    {
        type Error = error::Error;
        type Router = R;
        type Scriber = M;
        type Kdf = K; 

        fn new() -> Result<Self,  crate::abstraction::error::Error<Self>> 
        {
            let cli = interface::cli::Cli::parse();

            match &cli.command {
                interface::cli::Command::Read { path, password } => {
                    // 1. Инициализация пути и роутера           

                    let resource_path = <<Self::Router as crate::abstraction::Router>::Resource as UnifiedResourceIdentifierAbstraction>::Path::new(
                        path.to_string(), 
                        crate::abstraction::Operation::Open
                    ).map_err(|e| crate::abstraction::error::Error::<Self>::ResourcePathError(e))?;
                    
                    // Создаем ресурс для получения размера
                    let mut resource = <Self::Router as crate::abstraction::Router>::Resource::new(
                        resource_path.clone(), 
                        crate::abstraction::Operation::Open
                    ).map_err(|e| crate::abstraction::error::Error::<Self>::ResourcePathError(e))?;
                    
                    let file_size: usize = resource.path().size();
                    
                    // Создаем Роутер для операций чтения
                    let mut router: Self::Router = <Self::Router as crate::abstraction::Router>::new(resource_path, None);
                    
                    // 2. ЧТЕНИЕ ВСЕГО ФАЙЛА В БУФЕР (Операционный шаг 1)
                    let mut buf: Vec<u8> = vec![0u8; file_size];
                    router.read(&mut buf).map_err(|e| crate::abstraction::error::Error::<Self>::ReaderError(e))?;
                    
                    // 3. ИЗВЛЕЧЕНИЕ ЗАГОЛОВКА (Scriber)
                    let scriber: Self::Scriber = <Self::Scriber as crate::abstraction::Header>::read_from_buffer(&buf)
                        .map_err(|e| crate::abstraction::error::Error::<Self>::HeaderError(e))?;
                    
                    // 4. ГЕНЕРАЦИЯ КЛЮЧА
                    let salt = scriber.get_salt();
                    let nonce = scriber.get_nounce();
                    
                    let secret_password: <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Secret = <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Secret::new(password.clone()); // Пароль как Secret
                    let params: <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Params = <<<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Params as core::default::Default>::default(); // Предполагаем Default для параметров

                    let derive_key = <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf>::new(
                        secret_password,
                        params,
                        salt,
                        nonce,
                    );
                    
                    // 6. ФИНАЛЬНАЯ СБОРКА ПРИЛОЖЕНИЯ
                    Ok(App {
                        buffer: buf, // Считанные данные
                        resource: router, // Роутер
                        scriber: scriber, // Прочитанный заголовок
                        key_deriver: derive_key, // KDF генератор ключей
                        cli: cli,
                        _marker_f: PhantomData::default(),
                        _marker_n: PhantomData::default(),
                        _marker_s: PhantomData::default(),
                    })
                },
                interface::cli::Command::Prepare {
                    path_inner,
                    path_outer,
                    password,
                    cipher,
                } => {
                    // 1. Инициализация путей и роутера    
                    let path_inner: <<Self::Router as crate::abstraction::Router>::Resource as crate::abstraction::UnifiedResourceIdentifierAbstraction>::Path = <<Self::Router as crate::abstraction::Router>::Resource as crate::abstraction::UnifiedResourceIdentifierAbstraction>::Path::new(path_inner.to_string(), crate::abstraction::Operation::Open).map_err(|e| crate::abstraction::error::Error::<Self>::ResourcePathError(e))?;
                    let path_outer: Option<<<R as crate::abstraction::Router>::Resource as crate::abstraction::UnifiedResourceIdentifierAbstraction>::Path> = match path_outer {
                        Some(path) => {
                         Some(<<Self::Router as crate::abstraction::Router>::Resource as crate::abstraction::UnifiedResourceIdentifierAbstraction>::Path::new(path.to_string(), crate::abstraction::Operation::Create).map_err(|e| crate::abstraction::error::Error::<Self>::ResourcePathError(e))?)
                        },
                        None => Some(path_inner.clone()),
                    };
                    let mut resource_inner: <Self::Router as crate::abstraction::Router>::Resource = <Self::Router as crate::abstraction::Router>::Resource::new(path_inner, crate::abstraction::Operation::Open).map_err(|e| crate::abstraction::error::Error::<Self>::ResourcePathError(e))?;
                    
                    let size: usize = resource_inner.path().size();
                    let mut buf: Vec<u8> = vec![0u8; size];
                    

                    // Создаем Роутер для операций чтения
                    let mut router: Self::Router = <Self::Router as crate::abstraction::Router>::new(resource_inner.path().clone(), path_outer);
                    
                    // 2. Чтение файла в буфер
                    router.read(&mut buf).map_err(|e| crate::abstraction::error::Error::<Self>::ReaderError(e))?;

                    let salt = <Self::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Salt::generate().map_err(|e| crate::abstraction::error::Error::SaltError(e))?;
                    let nonce = <Self::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Nonce::generate(&password, salt.as_bytes()).map_err(|e| crate::abstraction::error::Error::NonceError(e))?;
                    let format = resource_inner.type_resource().map_err(|e| crate::abstraction::error::Error::FormatListError(e))?;
                     // 3. Создание подписи
                    let scriber: Self::Scriber = <Self::Scriber as crate::abstraction::Header>::new(format, cipher.clone(), salt.clone(), nonce.clone());
                    
                    let secret_password: <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Secret = <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Secret::new(password.clone()); // Пароль как Secret
                    let params: <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Params = <<<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Params as core::default::Default>::default(); // Предполагаем Default для параметров

                    let derive_key = <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf>::new(
                        secret_password,
                        params,
                        salt,
                        nonce,
                    );
                    
                    Ok(App{
                        buffer: buf,
                        resource: router,
                        scriber: scriber,
                        key_deriver: derive_key,
                        cli: cli,
                        _marker_f: PhantomData::default(),
                        _marker_n: PhantomData::default(),
                        _marker_s: PhantomData::default(),
                    })
                },
                interface::cli::Command::Decrypt {
                    path_inner,
                    path_outer,
                    password,
                } => {
                    // 1. Инициализация путей и роутера    
                    let path_inner: <<Self::Router as crate::abstraction::Router>::Resource as crate::abstraction::UnifiedResourceIdentifierAbstraction>::Path = <<Self::Router as crate::abstraction::Router>::Resource as crate::abstraction::UnifiedResourceIdentifierAbstraction>::Path::new(path_inner.to_string(), crate::abstraction::Operation::Open).map_err(|e| crate::abstraction::error::Error::<Self>::ResourcePathError(e))?;
                    let path_outer: Option<<<R as crate::abstraction::Router>::Resource as crate::abstraction::UnifiedResourceIdentifierAbstraction>::Path> = match path_outer {
                        Some(path) => {
                         Some(<<Self::Router as crate::abstraction::Router>::Resource as crate::abstraction::UnifiedResourceIdentifierAbstraction>::Path::new(path.to_string(), crate::abstraction::Operation::Create).map_err(|e| crate::abstraction::error::Error::<Self>::ResourcePathError(e))?)
                        },
                        None => Some(path_inner.clone()),
                    };
                    let mut resource_inner: <Self::Router as crate::abstraction::Router>::Resource = <Self::Router as crate::abstraction::Router>::Resource::new(path_inner, crate::abstraction::Operation::Open).map_err(|e| crate::abstraction::error::Error::<Self>::ResourcePathError(e))?;
                    
                    let size: usize = resource_inner.path().size();
                    let mut buf: Vec<u8> = vec![0u8; size];
                    

                    // Создаем Роутер для операций чтения
                    let mut router: Self::Router = <Self::Router as crate::abstraction::Router>::new(resource_inner.path().clone(), path_outer);
                    
                    // 2. ЧТЕНИЕ ВСЕГО ФАЙЛА В БУФЕР (Операционный шаг 1)
                    router.read(&mut buf).map_err(|e| crate::abstraction::error::Error::<Self>::ReaderError(e))?;

                    // 3. ИЗВЛЕЧЕНИЕ ЗАГОЛОВКА (Scriber)
                    let scriber: Self::Scriber = <Self::Scriber as crate::abstraction::Header>::read_from_buffer(&buf)
                        .map_err(|e| crate::abstraction::error::Error::<Self>::HeaderError(e))?;
                    
                    // 4. Генерация ключа
                    let salt = scriber.get_salt();
                    let nonce = scriber.get_nounce();
                    
                    let secret_password: <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Secret = <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Secret::new(password.clone()); // Пароль как Secret
                    let params: <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Params = <<<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Params as core::default::Default>::default(); // Предполагаем Default для параметров

                    let derive_key = <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf>::new(
                        secret_password,
                        params,
                        salt,
                        nonce,
                    );
                    
                    Ok(App{
                        buffer: buf,
                        resource: router,
                        scriber: scriber,
                        key_deriver: derive_key,
                        cli: cli,
                        _marker_f: PhantomData::default(),
                        _marker_n: PhantomData::default(),
                        _marker_s: PhantomData::default(),
                    })
                },
            }
        }

        fn run(&mut self) -> Result<(), crate::abstraction::error::Error<Self>> {
            let size: usize = K::KEY_LENGTH;
            let mut buffer = vec![0u8; size];
            self.key_deriver.derive_key(&mut buffer).map_err(|e| crate::abstraction::error::Error::KDFError(e))?;
            let cipher = self.scriber.get_cipher().build(&mut buffer).map_err(|e| crate::abstraction::error::Error::EncryptionListError(e))?;
            let mut res_buf = match &self.cli.command {
                interface::cli::Command::Prepare{..} =>{
                    let mut res_buf = vec![0u8; self.buffer.len() + 42]; // 42 так как подпись
                    cipher.encode(&mut self.buffer);
                    self.scriber.write_to_buffer(&mut self.buffer, &mut res_buf); 
                    res_buf
                },
                interface::cli::Command::Read{..} => {
                    let mut res_buf = vec![0u8; self.buffer.len() - 42];
                    self.scriber.remove_from_buffer(&mut self.buffer, &mut res_buf);
                    cipher.decode(&mut res_buf);
                    self.scriber.get_format().print_function(&mut res_buf);
                    return Ok(());
                },
                interface::cli::Command::Decrypt{..} => {
                    println!("{:?}", self.scriber.to_byte());
                    let mut res_buf = vec![0u8; self.buffer.len() - 42];
                    self.scriber.remove_from_buffer(&mut self.buffer, &mut res_buf);
                    cipher.decode(&mut res_buf);
                    res_buf
                },
            };
            
            self.resource.write(
                &mut res_buf
            ).map_err(|e| crate::abstraction::error::Error::WriterError(e))?;

            Ok(())
        }
    }
}

type Applicat = management::App<
    management::router::Router<
        realisation::object::file::FileResourceIdentifier
    >, 
    management::scriber::Scriber<
        realisation::object::file::resource_type::ResourceType,
        realisation::encryption::CryptoFormat,
        realisation::derive_key::chacha::salt::StandardSalt,
        realisation::derive_key::chacha::nonce::ChaChaNonce,
    >,
    realisation::derive_key::chacha::ChaChaKdf<32>,
    realisation::object::file::resource_type::ResourceType,
    realisation::derive_key::chacha::salt::StandardSalt,
    realisation::derive_key::chacha::nonce::ChaChaNonce,

>;

fn main() -> Result<(), crate::abstraction::error::Error<Applicat>> {
    let mut app = Applicat::new()?;
    app.run()
}
