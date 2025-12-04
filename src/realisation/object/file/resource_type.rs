
pub mod common;
pub mod error;

#[derive(Debug, Clone)]
pub enum ResourceType {
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
                        let text: std::borrow::Cow<str> =
                            String::from_utf8_lossy(bytes);
                        println!("--- Дешифрованный ТЕКСТ (TXT) ---");
                        println!("{}", text);
                        println!("----------------------------------");
                    }
                    file_format::FileFormat::OfficeOpenXmlDocument => {
                        println!("--- Дешифрованный DOCX ---");
                        // Используем docx-rs для чтения из байтов
                        match docx_rs::read_docx(bytes) {
                            Ok(docx) => {
                                let text = common::extract_text_from_docx(&docx);
                                println!("{}", text);
                            }
                            Err(e) => {
                                println!("Ошибка парсинга DOCX файла: {:?}", e);
                            }
                        }
                        println!("----------------------------");
                    }
                    _ => {
                        println!(
                            "--- Дешифрованные БИНАРНЫЕ ДАННЫЕ (Формат: {:?}) ---",
                            f
                        );
                        let slice_len = std::cmp::min(bytes.len(), 128);
                        println!(
                            "Первые {} байт: {:?}",
                            slice_len,
                            &bytes[..slice_len]
                        );
                        println!(
                            "--------------------------------------------------"
                        );
                    }
                }
            }
            _ => {
                println!("--- Дешифрованные БИНАРНЫЕ ДАННЫЕ (Неизвестный тип) ---");
                let slice_len = std::cmp::min(bytes.len(), 128);
                println!("Первые {} байт: {:?}", slice_len, &bytes[..slice_len]);
                println!("--------------------------------------------------");
            }
        }
    }
    fn to_byte(&self) -> u8 {
        match self {
            ResourceType::FileFormat(
                file_format::FileFormat::OfficeOpenXmlDocument,
            ) => 3,
            ResourceType::FileFormat(file_format::FileFormat::PlainText) => 2,
            ResourceType::Crypted => 1,
            _ => 0,
        }
    }
    fn from_byte(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            3 => Ok(ResourceType::FileFormat(
                file_format::FileFormat::OfficeOpenXmlDocument,
            )),
            2 => Ok(ResourceType::FileFormat(file_format::FileFormat::PlainText)),
            1 => Ok(ResourceType::Crypted),
            0 => Ok(ResourceType::UnknowFormat),
            _ => Err(Self::Error::BrokenByteFormat),
        }
    }
}