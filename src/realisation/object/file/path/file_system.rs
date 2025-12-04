
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
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match op {
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
            },
            Err(e) => Err(std::io::Error::new(
                e.kind(),
                format!("Ошибка при проверке пути '{}': {}", path.display(), e),
            )),
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