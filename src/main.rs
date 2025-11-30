pub mod abstraction {
    use std::fmt::Debug;


    /// Данный типаж абстрагирует шифрование и дешифрование данных
    pub trait Encryption {
        fn encode(&self, buf: &mut [u8]);
        fn decode(&self, buf: &mut [u8]);
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
            Self:Sized+Debug+ 'static,
    {
        type Error: core::error::Error + Send + Sync + 'static;


        fn to_byte(&self) -> u8;
        fn from_byte(byte: u8) -> Result<Self, Self::Error>;
    }
    
    pub trait EncryptionList 
        where
            Self: Sized+Debug+ 'static,
    {        
        type Error: core::error::Error + Send + Sync + 'static;
        type Data: Sized;
        type Encryptions: Encryption;
        
        fn build(&self, data: Self::Data) -> Result<Self::Encryptions, Self::Error>;
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
        fn type_resource(&mut self) -> Result<Self::Type, <Self as UnifiedResourceIdentifierAbstraction>::Error>;
    }

    // Стоит рассмотреть замену преобразований на TryForm
    pub trait MagicNumbers
        where
            Self: Sized
    {
        type Error: core::error::Error + Send + Sync + 'static;
        type Format: ResourceTypeList;
        type Chiper: EncryptionList;

        fn new(format: Self::Format, crypto: Self::Chiper) -> Self;
        fn to_byte(&self) -> [u8; 12];
        fn read_from_buffer(buf: &[u8; 12]) -> Result<Self, Self::Error>;
        fn write_to_buffer(&mut self, old_buf: &mut [u8], new_buf: &mut [u8]);
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
        type Scriber: MagicNumbers;

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
            MagicNumbersError(<A::Scriber as MagicNumbers>::Error),
            FormatListError(<<A::Scriber as MagicNumbers>::Format as ResourceTypeList>::Error),
            EncryptionListError(<<A::Scriber as MagicNumbers>::Chiper as EncryptionList>::Error),
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
                    Error::MagicNumbersError(e) => write!(f, "Ошибка подписи файла: {}", e),
                }
            }
        }

        impl<A> core::error::Error for Error<A>
            where 
                A: Application + core::fmt::Debug,
                A::Router: UnifiedResourceIdentifierAbstraction + core::fmt::Debug,
                A::Scriber: MagicNumbers + core::fmt::Debug,
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
                    Error::MagicNumbersError(e) => Some(e),
                }
            }
        }


    }


}

pub mod realisation {

    pub mod encryption {
        use clap::Subcommand;
        use crate::{abstraction::Encryption, realisation::encryption::{xor::XorEncryption}};

        /// Форматы шифрования
        #[derive(Debug)]
        pub enum CryptoFormat {
            XOR,
            None,
        }

        #[derive(Debug)]
        pub enum EncryptionRealisation {
            XORRealisation(XorEncryption),
        }

        impl Encryption for EncryptionRealisation {
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

        #[derive(Subcommand, Debug)]
        pub enum DataCrypto {
            XOR{key: u8},
            None,
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


        impl crate::abstraction::EncryptionList for CryptoFormat {
            type Error = error::Error;
            type Data = DataCrypto;
            type Encryptions = EncryptionRealisation;

            fn build(&self, data: Self::Data) -> Result<Self::Encryptions, Self::Error> {
                match (self, data) {
                    (CryptoFormat::XOR, DataCrypto::XOR{key}) => Ok(EncryptionRealisation::XORRealisation( XorEncryption::new(key))),
                    (CryptoFormat::XOR, _) => Err(Self::Error::IncorectDataEncryption),
                    (CryptoFormat::None, _) => Err(Self::Error::NoneExistEncryption),
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

        pub mod xor {
            use crate::abstraction::Encryption;
            #[derive(Debug)]
            pub struct XorEncryption {
                key: u8,
            }

            impl XorEncryption {
                pub fn new(key: u8) -> Self {
                    XorEncryption { key }
                }
            }

            impl Encryption for XorEncryption {
                fn encode(&self, buf: &mut [u8]) {
                    for byte in buf.iter_mut() {
                        *byte = *byte ^ self.key;
                    }
                }

                fn decode(&self, buf: &mut [u8]) {
                    for byte in buf.iter_mut() {
                        *byte = *byte ^ self.key;
                    }
                }
            }

            
        }
    }

    pub mod object {
        pub mod file {
            use std::io::{Read, Write};

            use crate::abstraction::{ResourcePath, UnifiedResourceIdentifierAbstraction};

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
                            println!("ha");
                            let path = std::path::PathBuf::from(path);
                            match std::fs::metadata(&path) {
                                Ok(metadata) => {
                                    if metadata.is_file() {
                                        println!("hat");
                                        Ok(FilePath(path))
                                    } else {
                                        println!("har");
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
                                    println!("has");
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
                                    println!("has");
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

                #[derive(Debug)]
                pub enum ResourceType{
                    FileFormat(file_format::FileFormat),
                    Crypted,
                    UnknowFormat,
                }

                impl crate::abstraction::ResourceTypeList for ResourceType {
                    type Error = error::Error;
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
                    }

                    impl core::fmt::Display for Error
                    {
                        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
                            match self {
                                Self::UnknowFormat => write!(f, "Формат файла не поддерживается"),
                                Self::BrokenByteFormat => write!(f, "Ошибка подписи байта формата файла магического числа"),
                            }
                        }
                    }

                    impl core::error::Error for Error
                    {
                        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
                            match self {
                                Self::UnknowFormat => None,
                                Self::BrokenByteFormat => None,
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
                            println!("dw");
                            Ok(FileResourceIdentifier { file, path: path })
                        }
                        crate::abstraction::Operation::Create => {
                            println!("{:#?}, 3", path.get_path());
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

                fn type_resource(&mut self) -> Result<Self::Type, <Self as UnifiedResourceIdentifierAbstraction>::Error> {
                    match file_format::FileFormat::from_reader(&mut self.file) {
                        Ok(r) => Ok(Self::Type::FileFormat(r)),
                        Err(e) => Err(e),
                    }
                }
            }
        }
    }
}

pub mod management {
    use core::cmp::PartialOrd;

    use clap::{error::Error, Parser};
    use docx_rs::DataBinding;
    use file_format::FileFormat;
    use crate::{abstraction::{ EncryptionList, ResourcePath, ResourceTypeList, UnifiedResourceIdentifierAbstraction}, realisation::{encryption::{CryptoFormat, DataCrypto}, object::file}};



    pub mod scriber {
        use std::io::Write;

        /// Записывается в начало шифрованного файла стационарно 12 байт, 1 - 3, 12 - 243
        pub struct  Scriber<RT, CA>
            where 
                RT: crate::abstraction::ResourceTypeList,
                CA: crate::abstraction::EncryptionList,
        {
            /// Второй байт
            format: RT,
            /// Третий байт
            crypto: CA,
            // Остальные байты заполненны нулями
        }

        impl<RT, CA> crate::abstraction::MagicNumbers for Scriber<RT, CA>
            where 
                RT: crate::abstraction::ResourceTypeList,
                CA: crate::abstraction::EncryptionList,
        {
            type Error = error::Error<RT, CA>;
            type Chiper = CA;
            type Format = RT;

            fn new(format: Self::Format, crypto: Self::Chiper) -> Self {
                Self {format, crypto}
            }

            fn to_byte(&self) -> [u8; 12] {
                [3, self.format.to_byte(), self.crypto.to_byte(),0, 0, 0, 0, 0, 0, 0, 0, 243]
            }

            fn read_from_buffer(buf: &[u8; 12]) -> Result<Self, Self::Error> {
                if buf[0] != 3 && buf[11] != 243 {
                    return  Err(Self::Error::NotFoundSubscribe);
                }
                let format = Self::Format::from_byte(buf[1]).map_err(|e| Self::Error::FormatError(e) )?;
                let chiper = Self::Chiper::from_byte( buf[2]).map_err(|e| Self::Error::ChiperError(e) )?;
                
                Ok(Self{
                        format:format,
                        crypto:chiper,
                })
            }

            fn write_to_buffer(&mut self, old_buf: &mut [u8], new_buf: &mut [u8]) {
                let mut res = self.to_byte().to_vec();         
                res.extend_from_slice(old_buf);
                new_buf.copy_from_slice(&res);  
            }

        }

        pub mod error {
            #[derive(Debug)]
            pub enum Error<RT, CA>
                where 
                    RT: crate::abstraction::ResourceTypeList,
                    CA: crate::abstraction::EncryptionList,
            {
                NotFoundSubscribe,
                FormatError(RT::Error),
                ChiperError(CA::Error)
            }

            impl<RT, CA> core::fmt::Display for Error<RT, CA>
                where 
                    RT: crate::abstraction::ResourceTypeList,
                    CA: crate::abstraction::EncryptionList,
            {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
                    match self {
                        Self::NotFoundSubscribe => write!(f, "Подпись файла не найдена"),
                        Self::FormatError(e) => write!(f, "Неправильно указан формат данных {}", e),
                        Self::ChiperError(e) => write!(f, "Неправильно указан формат шифрования {}", e),
                    }
                }
            }

            impl<RT, CA> core::error::Error for Error<RT, CA>
                where 
                    RT: crate::abstraction::ResourceTypeList,
                    CA: crate::abstraction::EncryptionList,
            {
                fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
                    match self {
                        Self::NotFoundSubscribe => None,
                        Self::FormatError(e) => Some(e),
                        Self::ChiperError(e) => Some(e),
                    }
                }
            }
        }
    }

    pub mod interface {

        pub mod cli {
            #[derive(clap::Parser)]
            pub struct Cli {
                #[command(subcommand)]
                pub command: Command,
            }

            #[derive(clap::Subcommand)]
            pub enum Command {
                ///Шифрование файла, аргумент - путь до файла
                Prepare {
                    path_inner: String,
                    #[arg(short, long)]
                    path_outer: Option<String>,
                    #[command(subcommand)]
                    chiper_algorithm: crate::realisation::encryption::DataCrypto,
                },
                ///Чтение файла, аргумент - путь до файла
                Read { path: String },
                ///Расшифровка файла, аргумент - путь до файла
                Decrypt {
                    path_inner: String,
                    #[arg(short, long)]
                    path_outer: Option<String>,
                },
            }
        }
    }
    
    pub mod router {
        use crate::abstraction::{ResourcePath, UnifiedResourceIdentifierAbstraction};

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
            type Error = error::Error<U>;
            type Resource = U;
            
            fn new(inner: U::Path, out: Option<U::Path>) -> Self {
                Router { inner, out }
            }

            fn resource(&self) -> Result<Self::Resource, <Self as crate::abstraction::Router>::Error> {
                U::new(self.inner.clone(), crate::abstraction::Operation::Open)
            }
        }


        impl<U> crate::abstraction::Writer for Router<U>
            where 
               U: crate::abstraction::UnifiedResourceIdentifierAbstraction,
               U::Path: crate::abstraction::ResourcePath
        {
            type Error = error::Error;
            
            fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {

                let mut resource = U::new(self.out.clone(), crate::abstraction::Operation::Write)
                    .map_err(|e| e.into())?;

                resource.write(buf).map_err(|e| e.into())
            }
        }

        impl<U> crate::abstraction::Reader for Router<U>
            where 
                U: crate::abstraction::UnifiedResourceIdentifierAbstraction,
                U::Path: crate::abstraction::ResourcePath
        {
            type Error = error::Error;
            
            fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
                let mut inr = U::new(self.inner.clone(), crate::abstraction::Operation::Open)
                .map_err(|e| e.into())?;
            
                inr.read(buf).map_err(|e| e.into())
            }
        }

        // impl<R: crate::abstraction::ResourcePath> Router<R> {

        //     pub fn type_resource<U: crate::abstraction::UnifiedResourceIdentifierAbstraction, S: crate::abstraction::AbstractError>(&self) -> Result<<U as crate::abstraction::UnifiedResourceIdentifierAbstraction>::Type, crate::abstraction::Error<U, S>>
        //     where
        //         U: crate::abstraction::UnifiedResourceIdentifierAbstraction<Path = R>,
        //         {
        //             let inr = U::new(self.inner.clone(), crate::abstraction::Operation::Open);
        //             match inr {
        //             Ok(mut i) => match i.type_resource() {
        //                 Ok(types) => Ok(types),
        //                 Err(e) => Err(crate::abstraction::Error::new(Box::new(e))),
        //             },
        //             Err(e) => Err(crate::abstraction::Error::new(Box::new(e))),
        //         }
        //         }

        //     pub fn write<U: crate::abstraction::UnifiedResourceIdentifierAbstraction, S: crate::abstraction::AbstractError>(
        //         &mut self,
        //         buf: &[u8],
        //         cli: &interface::cli::Cli,
        //         enc: crate::realisation::encryption::CryptoFormat,
        //     ) -> Result<usize, crate::abstraction::Error<U, S>>
        //     where
        //         U: crate::abstraction::UnifiedResourceIdentifierAbstraction<Path = R>,
        //     {
        //         // let outp = match self.out {
        //         //     Some(ref mut o) => match cli.command {
        //         //         Command::Prepare { .. } => o.add_extension_encryption(enc),
        //         //         Command::Decrypt { .. } => o.sub_extension_encryption(),
        //         //         Command::Read { .. } => o,
        //         //     },
        //         //     None => match cli.command {
        //         //         Command::Prepare { .. } => self.inner.add_extension_encryption(enc),
        //         //         Command::Decrypt { .. } => self.inner.sub_extension_encryption(),
        //         //         Command::Read { .. } => &self.inner,
        //         //     },
        //         // };
        //         //println!("{:#?}, 7", outp);
        //         //let outr = U::new(outp.clone(), crate::abstraction::Operation::Truncate);
        //         //println!("{:#?}, 10", outr);
        //         // match outr {
        //         //     Ok(mut o) => {
        //         //         println!("{:#?}, 9", o);
        //         //         match o.write(buf) {
        //         //             Ok(size) => {
        //         //                 return Ok(size);
        //         //             }
        //         //             Err(e) => {
        //         //                 return Err(crate::abstraction::Error::new(Box::new(e)));
        //         //             }
        //         //         }
        //         //     }
        //         //     Err(e) => Err(crate::abstraction::Error::new(Box::new(e))),
        //         // }
        //         Ok(9)
        //     }

        //     pub fn read<U>(
        //         &mut self,
        //         buf: &mut [u8],
        //         op: crate::abstraction::Operation,
        //     ) -> Result<usize, crate::abstraction::Error<U, S>>
        //     where
        //         U: crate::abstraction::UnifiedResourceIdentifierAbstraction<Path = R>,
        //     {
        //         let inr = U::new(self.inner.clone(), op);
        //         match inr {
        //             Ok(mut i) => match i.read(buf) {
        //                 Ok(size) => Ok(size),
        //                 Err(e) => Err(crate::abstraction::Error::new(Box::new(e))),
        //             },
        //             Err(e) => Err(crate::abstraction::Error::new(Box::new(e))),
        //         }
        //     }

        // }

        pub mod error {
            use crate::abstraction::UnifiedResourceIdentifierAbstraction;

            #[derive(Debug)]
            pub enum Error<U> 
                where 
                    U: UnifiedResourceIdentifierAbstraction,
            {
                ResourcePathError(<<U as crate::abstraction::UnifiedResourceIdentifierAbstraction>::Path as crate::abstraction::ResourcePath>::Error),
            }

            impl<U> core::fmt::Display for Error<U>
                where 
                    U: UnifiedResourceIdentifierAbstraction,
            {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
                    match self {
                        Self::ResourcePathError(e) => write!(f, "Ошибка пути ресурса {}", e),
                    }
                }
            }

            impl<U> core::error::Error for Error<U>
                where 
                    U: UnifiedResourceIdentifierAbstraction,
            {
                fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
                    match self {
                        Self::ResourcePathError(e) => Some(e),
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
    

    pub struct App<R, M>
        where 
            R: crate::abstraction::Router,
            M: crate::abstraction::MagicNumbers,
    {
        buffer: Vec<u8>,
        resource: R,
        scriber: M,
        cli: interface::cli::Cli,
    }

    impl<R, M> crate::abstraction::Application for  App<R, M>
        where
            R: crate::abstraction::Router,
            M: crate::abstraction::MagicNumbers,
    {
        type Error = error::Error;
        type Router = R;
        type Scriber = M;

        fn new() -> Result<Self,  crate::abstraction::error::Error<Self>>
        {
            let cli = interface::cli::Cli::parse();

            match &cli.command {
                interface::cli::Command::Read { path } => {
                    let resource: <Self::Router as crate::abstraction::Router>::Resource = <<Self::Router as crate::abstraction::Router>::Resource as crate::abstraction::UnifiedResourceIdentifierAbstraction>::Path::new(path.to_string(), crate::abstraction::Operation::Open)?;
                    let size: usize = resource.path().size();
                    let mut buf: Vec<u8> = vec![0u8; size];
                    let mut router = Self::Router::new( resource.path(), None);
                    router.read(&mut buf)?;
                    let scriber: Self::Scriber  = <Self::Scriber>::read_from_buffer(&buf)?;
                    App{
                        buffer: buf,
                        resource: router,
                        scriber: scriber,
                        cli: cli,
                    }

                },
                interface::cli::Command::Prepare {
                    path_inner,
                    path_outer,
                    chiper_algorithm,
                } => {
                    let chiper = chiper_algorithm;
                    let mut resource_inner: <Self::Router as crate::abstraction::Router>::Resource = <<Self::Router as crate::abstraction::Router>::Resource as crate::abstraction::UnifiedResourceIdentifierAbstraction>::Path::new(path_inner.to_string(), crate::abstraction::Operation::Open)?;
                    let mut resource_outer: Option<<Self::Router as crate::abstraction::Router>::Resource> = match path_outer {
                        Some(path) => Ok(<<Self::Router as crate::abstraction::Router>::Resource as crate::abstraction::UnifiedResourceIdentifierAbstraction>::Path::new(path.to_string(), crate::abstraction::Operation::Create)?),
                        None => None,
                    };
                    let size: usize = resource_inner.path().size();
                    let mut buf: Vec<u8> = vec![0u8; size];
                    let mut scriber = Self::Scriber::new(resource_inner.type_resource()?, chiper);
                    let mut router = match resource_outer {
                        Some(p) => Self::Router::new( resource_inner.path(), p.path()),
                        None => Self::Router::new( resource_inner.path(),  None),
                    };
                    router.read(&buf)?;
                    App{
                        buffer: buf,
                        resource: router,
                        scriber: scriber,
                        cli: cli,
                    }
                },
                interface::cli::Command::Decrypt {
                    path_inner,
                    path_outer,
                } => {
                    let mut resource_inner: <Self::Router as crate::abstraction::Router>::Resource = <<Self::Router as crate::abstraction::Router>::Resource as crate::abstraction::UnifiedResourceIdentifierAbstraction>::Path::new(path_inner.to_string(), crate::abstraction::Operation::Open)?;
                    let mut resource_outer: Option<<Self::Router as crate::abstraction::Router>::Resource> = match path_outer {
                        Some(path) => Ok(<<Self::Router as crate::abstraction::Router>::Resource as crate::abstraction::UnifiedResourceIdentifierAbstraction>::Path::new(path.to_string(), crate::abstraction::Operation::Create)?),
                        None => None,
                    };
                    let size: usize = resource_inner.path().size();
                    let mut buf: Vec<u8> = vec![0u8; size];
                    let mut router = match resource_outer {
                        Some(p) => Self::Router::new( resource_inner.path(), p.path()),
                        None => Self::Router::new( resource_inner.path(),  None),
                    };
                    router.read(&buf)?;
                    let scriber: Self::Scriber  = <Self::Scriber>::read_from_buffer(&buf)?;
                    App{
                        buffer: buf,
                        resource: router,
                        scriber: scriber,
                        cli: cli,
                    }
                },
            }
        }

        fn run(&mut self, encrypt: crate::realisation::encryption::CryptoFormat) -> Result<(), crate::abstraction::Error<U, S>> {
            match &self.cli.command {
                interface::cli::Command::Prepare{..} => match encrypt.build() {
                    Ok(e) => {
                        let mut state: StateCryptoManagment;
                        match self.resource.type_resource::<U, S>() {
                            Ok(types) =>  StateCryptoManagment::new(types, CryptoFormat::XOR(0xAA)),
                            Err(e) => return Err(e),
                        };
                        e.encode(&mut self.buffer)
                    },
                    Err(e) => return Err(crate::abstraction::Error::new(Box::new(e))),
                },
                interface::cli::Command::Read{..} => {
                //    let ext = self.resource.inner.extension();
                //    println!("{:#?}", ext);
                //    ext.1.build().ok_or_else(|| {
                //    crate::abstraction::Error::new(Box::new(std::io::Error::new(
                //       std::io::ErrorKind::InvalidInput,
                //       "Не удалось создать дешифратор: формат дешифрования не поддерживается."
                //    )))
                // })?.decode(&mut self.buffer);
                //    match ext {
                //       crate::abstraction::FileFormat::TXT => {
                //          println!("Текст: {}", String::from_utf8_lossy(&self.buffer).to_string());
                //          return Result::Ok(());
                //       }
                //       crate::abstraction::FileFormat::DOCX => {
                //          // match R {
                //          //    Ok(text) => {
                //          //       println!("Текст из DOCX: {}", text);
                //          //       return Result::Ok(());
                //          //    }
                //          //    Err(e) => {
                //          //       return Err(Error::new(Box::new(e))); 
                //          //    }
                //          // }
                //       }
                //       _ => return Err(crate::abstraction::Error::new(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Формат файла не поддерживается для данной комманды"))))),
                //    }
                },
                interface::cli::Command::Decrypt{..} => match encrypt.build() {
                    Ok(e) => e.decode(&mut self.buffer),
                    Err(e) => return Err(crate::abstraction::Error::new(Box::new(e))),
                },
            };
            println!("{:?}", String::from_utf8(self.buffer.to_vec()));
            Ok(())
            // match self.resource.write(&self.buffer, &self.cli, encrypt) {
            //     Ok(_) => Result::Ok(()),
            //     Err(e) => Result::Err(e),
            // }
        }
    }
}

fn main() -> Result<(), crate::abstraction::error::Error<impl crate::abstraction::Application>> {
    let mut app = management::App::<realisation::object::file::FileResourceIdentifier>::new()?;
    app.run(realisation::encryption::CryptoFormat::XOR(0xAA))
}
