//! PE data structures

use windows::Win32::System::Diagnostics::Debug::{IMAGE_DATA_DIRECTORY, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64};
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;

/// Internal structure for export table data
pub(crate) struct ExportTableData {
    pub section_count: u16,
    pub section_table_offset: usize,
    pub export_directory: IMAGE_DATA_DIRECTORY,
}

/// Represents a relocation entry from a PE file
/// 
/// Used for processing base relocations in process hollowing
#[derive(Debug, Copy, Clone)]
pub struct RelocationEntry {
    data: u16,
}

// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only
impl RelocationEntry {
    /// Creates a new relocation entry from raw data
    pub fn new(data: u16) -> Self {
        RelocationEntry { data }
    }

    /// Gets the offset field (lower 12 bits)
    pub fn offset(&self) -> u16 {
        self.data & 0x0FFF
    }

    /// Gets the type field (upper 4 bits)
    pub fn type_(&self) -> u8 {
        (self.data >> 12) as u8
    }
}

/// PE byte-level utilities for reading and writing addresses
pub mod utils {
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
}

/// Represents an export table from a PE file
#[derive(Default, Clone, Debug)]
pub struct ExportTable {
    /// Names of exported functions
    pub array_of_names: Vec<String>,
    /// Ordinals for each exported function
    pub array_of_ordinals: Vec<u32>,
}

/// Represents a parsed PE (Portable Executable) file
#[derive(Clone)]
pub struct PE {
    /// Whether this is an x64 PE file (true) or x86 (false)
    pub x64: bool,
    /// DOS header
    pub dos_header: IMAGE_DOS_HEADER,
    /// NT headers for x86
    pub nt_headers_x86: IMAGE_NT_HEADERS32,
    /// NT headers for x64
    pub nt_headers_x64: IMAGE_NT_HEADERS64,
    /// Raw PE binary data
    pub data: Vec<u8>,
    /// Export table
    pub export_table: ExportTable,
}

impl std::fmt::Debug for PE {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PE")
            .field("x64", &self.x64)
            .field("export_table", &self.export_table)
            .finish()
    }
}

impl PE {
    /// Returns true if the PE file is x64, false if x86
    pub fn is_x64(&self) -> bool {
        self.x64
    }

    /// Returns a reference to the export table
    pub fn get_export_table(&self) -> &ExportTable {
        &self.export_table
    }
}
