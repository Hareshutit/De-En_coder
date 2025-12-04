use crate::abstraction::ResourcePath;
use std::io::{Read, Write};

pub mod path;
pub mod resource_type;

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

    fn type_resource(
        &mut self,
    ) -> Result<Self::Type, <Self::Type as crate::abstraction::ResourceTypeList>::Error> {
        match file_format::FileFormat::from_reader(&mut self.file) {
            Ok(r) => Ok(Self::Type::FileFormat(r)),
            Err(e) => Err(crate::realisation::object::file::resource_type::error::Error::ReadError),
        }
    }
}
