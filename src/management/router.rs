pub mod error;

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
    U::Path: crate::abstraction::ResourcePath,
{
    type Error = error::Error;

    type Resource = U;

    fn new(inner: U::Path, out: Option<U::Path>) -> Self {
        Router { inner, out }
    }

    fn resource(&self) -> Result<Self::Resource, <Self as crate::abstraction::Router>::Error> {
        U::new(self.inner.clone(), crate::abstraction::Operation::Open)
            .map_err(|e| error::Error::ResourcePathError(Box::new(e)))
    }
}

impl<U> crate::abstraction::Writer for Router<U>
where
    U: crate::abstraction::UnifiedResourceIdentifierAbstraction,
    U::Path: crate::abstraction::ResourcePath,
{
    type Error = error::Error;

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let out = match self.out {
            Some(ref out) => out,
            None => return Err(Self::Error::BadWriteError),
        };

        let mut resource = U::new(out.clone(), crate::abstraction::Operation::Create)
            .map_err(|e| Self::Error::ResourcePathError(Box::new(e)))?;

        resource
            .write(buf)
            .map_err(|e| Self::Error::WriterError(Box::new(e)))
    }
}

impl<U> crate::abstraction::Reader for Router<U>
where
    U: crate::abstraction::UnifiedResourceIdentifierAbstraction,
    U::Path: crate::abstraction::ResourcePath,
{
    type Error = error::Error;

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut inr = U::new(self.inner.clone(), crate::abstraction::Operation::Open)
            .map_err(|e| Self::Error::ResourcePathError(Box::new(e)))?;

        inr.read(buf)
            .map_err(|e| Self::Error::ReaderError(Box::new(e)))
    }
}
