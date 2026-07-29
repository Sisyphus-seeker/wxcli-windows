use crate::error::KeychainError;

#[derive(Debug, Clone)]
pub struct MemRegion {
    pub start: u64,
    pub end: u64,
}

pub trait MemoryReader {
    fn rw_regions(&self) -> Result<Vec<MemRegion>, KeychainError>;
    fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, KeychainError>;
}
