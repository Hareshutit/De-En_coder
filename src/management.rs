use std::marker::PhantomData;
use crate::abstraction::Encryption;
use crate::abstraction::Secret;
use crate::{
    abstraction::{EncryptionList, ResourcePath, UnifiedResourceIdentifierAbstraction},
    realisation::encryption::CryptoFormat,
};
use clap::Parser;

pub mod scriber;
pub mod router;
pub mod error;
pub mod interface;

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
impl<R, M, K, F, S, N> crate::abstraction::Application for App<R, M, K, F, S, N>
where
    F: crate::abstraction::ResourceTypeList,
    R: crate::abstraction::Router<
            Resource: crate::abstraction::UnifiedResourceIdentifierAbstraction<Type = F>,
        >,
    M: crate::abstraction::Header<Format = F, Nonce = N, Salt = S, Cipher = CryptoFormat>,
    S: crate::abstraction::SaltProvider,
    N: crate::abstraction::NonceProvider,
    K: crate::abstraction::KeyDeriver<String, (), Salt = S, Nonce = N>,
{
    type Error = error::Error;
    type Router = R;
    type Scriber = M;
    type Kdf = K;
    fn new() -> Result<Self, crate::abstraction::error::Error<Self>> {
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
                    crate::abstraction::Operation::Open,
                )
                .map_err(|e| crate::abstraction::error::Error::<Self>::ResourcePathError(e))?;
                let file_size: usize = resource.path().size();
                // Создаем Роутер для операций чтения
                let mut router: Self::Router =
                    <Self::Router as crate::abstraction::Router>::new(resource_path, None);
                // 2. ЧТЕНИЕ ВСЕГО ФАЙЛА В БУФЕР (Операционный шаг 1)
                let mut buf: Vec<u8> = vec![0u8; file_size];
                router
                    .read(&mut buf)
                    .map_err(|e| crate::abstraction::error::Error::<Self>::ReaderError(e))?;
                // 3. ИЗВЛЕЧЕНИЕ ЗАГОЛОВКА (Scriber)
                let scriber: Self::Scriber =
                    <Self::Scriber as crate::abstraction::Header>::read_from_buffer(&buf)
                        .map_err(|e| {
                            crate::abstraction::error::Error::<Self>::HeaderError(e)
                        })?;
                // 4. ГЕНЕРАЦИЯ КЛЮЧА
                let salt = scriber.get_salt();
                let nonce = scriber.get_nounce();
                let secret_password: <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Secret = <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Secret::new(password.clone()); // Пароль как Secret
                let params: <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Params = <<<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Params as core::default::Default>::default(); // Предполагаем Default для параметров
                let derive_key =
                    <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf>::new(
                        secret_password,
                        params,
                        salt,
                        nonce,
                    );
                // 6. ФИНАЛЬНАЯ СБОРКА ПРИЛОЖЕНИЯ
                Ok(App {
                    buffer: buf,             // Считанные данные
                    resource: router,        // Роутер
                    scriber: scriber,        // Прочитанный заголовок
                    key_deriver: derive_key, // KDF генератор ключей
                    cli: cli,
                    _marker_f: PhantomData::default(),
                    _marker_n: PhantomData::default(),
                    _marker_s: PhantomData::default(),
                })
            }
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
                let mut resource_inner: <Self::Router as crate::abstraction::Router>::Resource =
                    <Self::Router as crate::abstraction::Router>::Resource::new(
                        path_inner,
                        crate::abstraction::Operation::Open,
                    )
                    .map_err(|e| {
                        crate::abstraction::error::Error::<Self>::ResourcePathError(e)
                    })?;
                let size: usize = resource_inner.path().size();
                let mut buf: Vec<u8> = vec![0u8; size];
                // Создаем Роутер для операций чтения
                let mut router: Self::Router =
                    <Self::Router as crate::abstraction::Router>::new(
                        resource_inner.path().clone(),
                        path_outer,
                    );
                // 2. Чтение файла в буфер
                router
                    .read(&mut buf)
                    .map_err(|e| crate::abstraction::error::Error::<Self>::ReaderError(e))?;
                let salt =
                    <Self::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Salt::generate()
                        .map_err(|e| crate::abstraction::error::Error::SaltError(e))?;
                let nonce =
                    <Self::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Nonce::generate(
                        &password,
                        salt.as_bytes(),
                    )
                    .map_err(|e| crate::abstraction::error::Error::NonceError(e))?;
                let format = resource_inner
                    .type_resource()
                    .map_err(|e| crate::abstraction::error::Error::FormatListError(e))?;
                // 3. Создание подписи
                let scriber: Self::Scriber = <Self::Scriber as crate::abstraction::Header>::new(
                    format,
                    cipher.clone(),
                    salt.clone(),
                    nonce.clone(),
                );
                let secret_password: <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Secret = <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Secret::new(password.clone()); // Пароль как Secret
                let params: <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Params = <<<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Params as core::default::Default>::default(); // Предполагаем Default для параметров
                let derive_key =
                    <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf>::new(
                        secret_password,
                        params,
                        salt,
                        nonce,
                    );
                Ok(App {
                    buffer: buf,
                    resource: router,
                    scriber: scriber,
                    key_deriver: derive_key,
                    cli: cli,
                    _marker_f: PhantomData::default(),
                    _marker_n: PhantomData::default(),
                    _marker_s: PhantomData::default(),
                })
            }
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
                let mut resource_inner: <Self::Router as crate::abstraction::Router>::Resource =
                    <Self::Router as crate::abstraction::Router>::Resource::new(
                        path_inner,
                        crate::abstraction::Operation::Open,
                    )
                    .map_err(|e| {
                        crate::abstraction::error::Error::<Self>::ResourcePathError(e)
                    })?;
                let size: usize = resource_inner.path().size();
                let mut buf: Vec<u8> = vec![0u8; size];
                // Создаем Роутер для операций чтения
                let mut router: Self::Router =
                    <Self::Router as crate::abstraction::Router>::new(
                        resource_inner.path().clone(),
                        path_outer,
                    );
                // 2. ЧТЕНИЕ ВСЕГО ФАЙЛА В БУФЕР (Операционный шаг 1)
                router
                    .read(&mut buf)
                    .map_err(|e| crate::abstraction::error::Error::<Self>::ReaderError(e))?;
                // 3. ИЗВЛЕЧЕНИЕ ЗАГОЛОВКА (Scriber)
                let scriber: Self::Scriber =
                    <Self::Scriber as crate::abstraction::Header>::read_from_buffer(&buf)
                        .map_err(|e| {
                            crate::abstraction::error::Error::<Self>::HeaderError(e)
                        })?;
                // 4. Генерация ключа
                let salt = scriber.get_salt();
                let nonce = scriber.get_nounce();
                let secret_password: <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Secret = <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Secret::new(password.clone()); // Пароль как Secret
                let params: <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Params = <<<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf as crate::abstraction::KeyDeriver<String, ()>>::Params as core::default::Default>::default(); // Предполагаем Default для параметров
                let derive_key =
                    <<App<R, M, K, F, S, N> as crate::abstraction::Application>::Kdf>::new(
                        secret_password,
                        params,
                        salt,
                        nonce,
                    );
                Ok(App {
                    buffer: buf,
                    resource: router,
                    scriber: scriber,
                    key_deriver: derive_key,
                    cli: cli,
                    _marker_f: PhantomData::default(),
                    _marker_n: PhantomData::default(),
                    _marker_s: PhantomData::default(),
                })
            }
        }
    }
    fn run(&mut self) -> Result<(), crate::abstraction::error::Error<Self>> {
        let size: usize = K::KEY_LENGTH;
        let mut buffer = vec![0u8; size];
        self.key_deriver
            .derive_key(&mut buffer)
            .map_err(|e| crate::abstraction::error::Error::KDFError(e))?;
        let cipher = self
            .scriber
            .get_cipher()
            .build(&mut buffer)
            .map_err(|e| crate::abstraction::error::Error::EncryptionListError(e))?;
        let mut res_buf = match &self.cli.command {
            interface::cli::Command::Prepare { .. } => {
                let mut res_buf = vec![0u8; self.buffer.len() + 42]; // 42 так как подпись
                cipher.encode(&mut self.buffer);
                self.scriber.write_to_buffer(&mut self.buffer, &mut res_buf);
                res_buf
            }
            interface::cli::Command::Read { .. } => {
                let mut res_buf = vec![0u8; self.buffer.len() - 42];
                self.scriber
                    .remove_from_buffer(&mut self.buffer, &mut res_buf);
                cipher.decode(&mut res_buf);
                self.scriber.get_format().print_function(&mut res_buf);
                return Ok(());
            }
            interface::cli::Command::Decrypt { .. } => {
                println!("{:?}", self.scriber.to_byte());
                let mut res_buf = vec![0u8; self.buffer.len() - 42];
                self.scriber
                    .remove_from_buffer(&mut self.buffer, &mut res_buf);
                cipher.decode(&mut res_buf);
                res_buf
            }
        };
        self.resource
            .write(&mut res_buf)
            .map_err(|e| crate::abstraction::error::Error::WriterError(e))?;
        Ok(())
    }
}