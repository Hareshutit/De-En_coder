use std::{io::{Read, Write}, path};
use clap::{Parser, Subcommand};

pub trait Encryption {
    fn encode(&self, buf: &mut [u8]);
    fn decode(&self, buf: &mut [u8]);
}

struct XorEncryption {
    key: u8,
}

impl XorEncryption {
    pub fn new(key: u8) -> Self {
        Self { key }
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

trait Reader {
    type Error: core::error::Error + Send + Sync + 'static;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
}

trait Writer {
    type Error: core::error::Error + Send + Sync + 'static;
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error>;
    fn flush(&mut self) -> Result<(), Self::Error>;
}

enum Operation {
    Open,
    Create,
}

trait ResourcePath
where Self: Sized{
    type Error: core::error::Error + Send + Sync + 'static;

    fn new(path: String, op: Operation) -> Result<Self, Self::Error>
    where 
        Self: Sized;
    fn size(&self) -> usize;
    fn join(&self, other: String) -> Self;
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ResourceKind {
    File,
    Unknown,
}


trait UnifiedResourceIdentifierAbstraction: Reader + Writer {
    type Path: ResourcePath;
    fn new(path: Self::Path, op: Operation) -> Result<Self, <Self::Path as ResourcePath>::Error>
    where
        Self: Sized;
    fn path(&self) -> &Self::Path;
}

struct FileResourceIdentifier {
    file: std::fs::File,
    path: FilePath,
}

impl Reader for FileResourceIdentifier {
    type Error = std::io::Error;

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.file.read_exact(buf)?;
        Ok(buf.len())
    }
    
}

impl Writer for FileResourceIdentifier {
    type Error = std::io::Error;

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.file.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.file.flush()
    }
}

struct FilePath(std::path::PathBuf);

impl ResourcePath for FilePath {
    type Error = std::io::Error;

    fn new(path: String, op: Operation) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let path = FilePath(std::path::PathBuf::from(path));
        if path.0.exists() {
            Ok(path) 
        } else {
            match op {
                Operation::Open => {
                    match path.0.to_str() {
                        Some(err) => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Файла по пути".to_string() + &err +&" не существует".to_string())),
                        None => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Некорректный путь".to_string())),
                    }
                }
                Operation::Create => Ok(path), 
            }
        }
    }

    fn size(&self) -> usize {
        match std::fs::metadata(&self.0) {
            Ok(metadata) => metadata.len() as usize,
            Err(_) => 0,
        }
    }

    fn join(&self, other: String) -> Self {
        let mut new_path = self.0.clone();
        new_path.push(&other);
        FilePath(new_path)
    }
}

impl UnifiedResourceIdentifierAbstraction for FileResourceIdentifier {
    type Path = FilePath;

    fn new(path: Self::Path, op: Operation) -> Result<Self, <Self::Path as ResourcePath>::Error>
    where
        Self: Sized,
    {
        match op {
            Operation::Open => {
                let file = std::fs::File::open(&path.0)?;
                Ok(FileResourceIdentifier{ file, path: path})
            }
            Operation::Create => {
                let file = std::fs::File::create(&path.0)?;
                Ok(FileResourceIdentifier{ file, path: path})
            }
        }
        
    }

    fn path(&self) -> &Self::Path {
        &self.path
    }

}

struct Storage<T: UnifiedResourceIdentifierAbstraction> {
    inner: T,
    out: T,
}

impl<T: UnifiedResourceIdentifierAbstraction> Storage<T> {
    fn new(inner: T, out: T) -> Self {
        Storage { inner, out }
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, <T as Writer>::Error> {
        self.out.write(buf)
    }
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, <T as Reader>::Error> {
        self.inner.read(buf)
    }
}


enum Error<T: UnifiedResourceIdentifierAbstraction> {
    WriterError(<T as Writer>::Error),
    ReaderError(<T as Reader>::Error),
    ResourcePath(<T::Path as ResourcePath>::Error),
}

impl<T: UnifiedResourceIdentifierAbstraction> Error<T> {
    fn new(e: Box<dyn core::error::Error + Send + Sync + 'static>) -> Self {   
        let e = match e.downcast::<<T as Writer>::Error>() {
            Ok(concrete_err) => return Error::WriterError(*concrete_err),
            Err(original_box) => original_box,
        };
        let e = match e.downcast::<<T as Reader>::Error>() {
            Ok(concrete_err) => return Error::ReaderError(*concrete_err),
            Err(original_box) => original_box,
        };
        let e = match e.downcast::<<T::Path as ResourcePath>::Error>() {
            Ok(concrete_err) => return Error::ResourcePath(*concrete_err),
            Err(original_box) => original_box,
        };
        panic!("Ошибка неизвестного типа: {}", e);
    }
}

enum ReadFormat {
    TXT,
    DOCX
}


#[derive(Parser)]
struct  Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    ///Шифрование файла, аргумент - путь до файла
    Prepare{
        path: String,
    },
    ///Чтение файла, аргумент - путь до файла
    Read{
        path: String,
    },
    ///Расшифровка файла, аргумент - путь до файла
    Decrypt{
        path: String,
    },
}

struct App<T: UnifiedResourceIdentifierAbstraction> {
    buffer: Vec<u8>,
    resource: Storage<T>,
    cli: Cli,
}

impl<T: UnifiedResourceIdentifierAbstraction>  App<T>  {
    // fn new(mut inner: T, mut outer: T) -> Result<Self, Error<T>> {
    //     let size: usize = inner.path().size();
    //     let mut buf: Vec<u8> = vec![0u8; size];
    //     match inner.read(&mut buf) {
    //         Ok(_) => {
    //            Result::Ok(App {
    //                buffer: buf,
    //                resource: Storage::new(inner, outer),
    //            })
    //         }
    //         Err(e  ) => {
    //             Result::Err(Error::new(Box::new(e)))
    //         }
    //     }
    // }

    fn new() -> Result<App<T>, Error<T>>
    where 
    T: UnifiedResourceIdentifierAbstraction,
    T::Path: ResourcePath, {
        let cli = Cli::parse();
        let mut inner = match &cli.command {
            Command::Read { path }| Command::Prepare { path } 
            | Command::Decrypt { path }  => {
                match T::Path::new(path.to_string(), Operation::Open) {
                    Ok(res_path) => {
                        match T::new(res_path, Operation::Open) {
                            Ok(res) => res,
                            Err(e) => return Err(Error::new(Box::new(e))),
                        }
                    },
                    Err(e) => return Err(Error::new(Box::new(e))),
                }
            },
        };

        let size: usize = inner.path().size();
        let mut buf: Vec<u8> = vec![0u8; size];
        let outer = T::new(inner.path().join("output.crypt".to_string()), Operation::Create);
        let outer = match outer {
            Ok(res) => res,
            Err(e) => return Err(Error::new(Box::new(e))),
        };
        match inner.read(&mut buf) {
            Ok(_) => {
               Result::Ok(App {
                   buffer: buf,
                   resource: Storage::new(inner, outer),
                   cli: cli,
               })
            },
            Err(e  ) => {
                Result::Err(Error::new(Box::new(e)))
            },
        }
    }

    fn run<E: Encryption>(&mut self, encrypt: E) -> Result<(), Error<T>> {
            match self.cli.command {
                Command::Prepare{path  } => encrypt.encode(&mut self.buffer),
                Command::Read{path  } => {
                match format {
                    ReadFormat::TXT => {
                        println!("Текст: {}", String::from_utf8_lossy(&self.buffer).to_string());
                        return Result::Ok(());
                    }
                    ReadFormat::DOCX => {
                        match extract_text_from_buffer(&self.buffer) {
                            Ok(text) => {
                                println!("Текст из DOCX: {}", text);
                                return Result::Ok(());
                            }
                            Err(e) => {
                                return Err(Error::new(Box::new(e))); 
                            }
                        }
                    }
                }
            },
            Command::Decrypt{path  } => encrypt.decode(&mut self.buffer),
        }
        match self.resource.out.write(&self.buffer) {
            Ok(_) => Result::Ok(()),
            Err(e) => Result::Err(Error::new(Box::new(e))),
        }
    }
}


fn main() -> Result<(), Box<Error<dyn core::error::Error + Send + Sync + 'static>>> {
    let app = App::<FileResourceIdentifier>::new()?;
    app.run(XorEncryption::new(0xAA))
}
