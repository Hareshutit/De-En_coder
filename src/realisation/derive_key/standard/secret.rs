/// Секрет (ключ) для Standard20. Должен быть 32 байта.
#[derive(Debug)]
pub struct StandardKey(pub Vec<u8>);
impl crate::abstraction::Secret<String> for StandardKey {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    fn new(k: String) -> Self {
        StandardKey(k.into_bytes())
    }
}