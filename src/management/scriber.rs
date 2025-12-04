pub mod error;

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

pub struct Scriber<RT, CA, SP, NP>
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

    fn new(
        format: Self::Format,
        cipher: Self::Cipher,
        salt: Self::Salt,
        nonce: Self::Nonce,
    ) -> Self {
        Self {
            format,
            cipher,
            version: 1,
            salt: salt,
            nonce: nonce,
        }
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

        let cipher =
            Self::Cipher::from_byte(buf[offset]).map_err(|e| Self::Error::CipherError(e))?;

        offset += 1;

        let format =
            Self::Format::from_byte(buf[offset]).map_err(|e| Self::Error::FormatError(e))?;

        offset += 1;

        offset += 5;

        let salt_slice = &buf[offset..offset + SP::SALT_SIZE];

        let salt = SP::from_bytes(salt_slice).map_err(|e| Self::Error::SaltError(e.into()))?;

        offset += SP::SALT_SIZE;

        let nonce_slice = &buf[offset..offset + NP::NONCE_SIZE];

        let nonce = NP::from_bytes(nonce_slice).map_err(|e| Self::Error::NonceError(e.into()))?;

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
