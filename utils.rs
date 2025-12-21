//! PE byte-level utilities for reading and writing binary data

/// Reads a 32-bit little-endian integer from bytes
pub fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    ((data[offset + 3] as u32) << 24)
        | ((data[offset + 2] as u32) << 16)
        | ((data[offset + 1] as u32) << 8)
        | data[offset] as u32
}

/// Reads a 16-bit little-endian integer from bytes
pub fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    ((data[offset + 1] as u16) << 8) | data[offset] as u16
}

/// Reads a 64-bit little-endian address from bytes
pub fn read_address(contents: &[u8], offset: usize) -> i64 {
    let slice = &contents[offset..offset + 8];
    let array: [u8; 8] = slice.try_into().expect("slice with incorrect length");
    i64::from_le_bytes(array)
}

/// Writes a 64-bit little-endian address to bytes
pub fn write_address(contents: &mut [u8], offset: usize, address: i64) {
    let bytes = address.to_le_bytes();
    contents[offset..offset + 8].copy_from_slice(&bytes);
}
