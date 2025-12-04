impl crate::abstraction::Params<()> for () {
    fn new(parametr: ()) -> Self {
        parametr
    }

    fn as_bytes(&self) -> &[u8] {
        &[]
    }
}
