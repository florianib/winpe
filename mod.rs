//! Windows PE Parser Library
//!
//! A Rust library for parsing Windows PE (Portable Executable) files.
//!
//! # Example
//!
//! ```no_run
//! use winpe::parse;
//! use std::fs;
//!
//! let data = fs::read("library.dll").expect("Could not read file");
//! let pe = parse(data);
//!
//! println!("Architecture: {}", if pe.is_x64() { "x64" } else { "x86" });
//! println!("Exported functions: {}", pe.get_export_table().array_of_names.len());
//! ```

use windows::Win32::System::Diagnostics::Debug::IMAGE_DATA_DIRECTORY;
use windows::Win32::System::Diagnostics::Debug::IMAGE_FILE_HEADER;
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER;
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows::Win32::System::SystemServices::IMAGE_DOS_SIGNATURE;
use windows::Win32::System::SystemServices::IMAGE_EXPORT_DIRECTORY;
use windows::Win32::System::SystemServices::IMAGE_NT_SIGNATURE;

// PE header constants
const PE_MAGIC_X64: u16 = 0x20b;  // Magic number for x64 PE files
const PE_MAGIC_X86: u16 = 0x10b;  // Magic number for x86 PE files
const PE_MAGIC_OFFSET: usize = 0x18; // Offset to magic number in NT headers

/// Parses a PE binary and extracts export table information
///
/// # Arguments
///
/// * `data` - Raw PE binary data
///
/// # Returns
///
/// A `PE` struct containing parsed information
///
/// # Panics
///
/// Panics if the binary is not a valid PE file
pub fn parse(data: Vec<u8>) -> PE {
    PE::build(data)
}

/// Reads a 32-bit little-endian integer from bytes
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    ((data[offset + 3] as u32) << 24)
        | ((data[offset + 2] as u32) << 16)
        | ((data[offset + 1] as u32) << 8)
        | data[offset] as u32
}

/// Reads a 16-bit little-endian integer from bytes
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    ((data[offset + 1] as u16) << 8) | data[offset] as u16
}

struct ExportTableData {
    section_count: u16,
    section_table_offset: usize,
    export_directory: IMAGE_DATA_DIRECTORY
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
    pub export_table: ExportTable
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

    fn build(data: Vec<u8>) -> PE {
        let dos_header = unsafe { *data.as_ptr().cast::<IMAGE_DOS_HEADER>() };
        let bitness = unsafe {
            *(data
                .as_ptr()
                .add(dos_header.e_lfanew as usize + PE_MAGIC_OFFSET)
                .cast::<u16>())
        };
        let nt_headers_x64: IMAGE_NT_HEADERS64;
        let nt_headers_x86: IMAGE_NT_HEADERS32;
        let x64: bool;

        if bitness == PE_MAGIC_X64 {
            nt_headers_x64 = unsafe {
                *(data
                    .as_ptr()
                    .add(dos_header.e_lfanew as usize)
                    .cast::<IMAGE_NT_HEADERS64>())
            };
            nt_headers_x86 = Default::default();
            x64 = true;
        } else if bitness == PE_MAGIC_X86 {
            nt_headers_x64 = Default::default();
            nt_headers_x86 = unsafe {
                *(data
                    .as_ptr()
                    .add(dos_header.e_lfanew as usize)
                    .cast::<IMAGE_NT_HEADERS32>())
            };
            x64 = false;
        } else {
            panic!("Unknown PE architecture: {:#x}", bitness);
        }

        let is_valid_dos = dos_header.e_magic == IMAGE_DOS_SIGNATURE;
        let is_valid_nt = if x64 {
            nt_headers_x64.Signature == IMAGE_NT_SIGNATURE
        } else {
            nt_headers_x86.Signature == IMAGE_NT_SIGNATURE
        };

        if !is_valid_dos || !is_valid_nt {
            panic!("Invalid PE binary file format");
        }

        let mut pe = PE {dos_header, x64, nt_headers_x64, nt_headers_x86, data, export_table: Default::default()};

        let export_table = pe.create_export_table();

        pe.export_table = export_table;

        pe
    }

    fn create_export_table(&self) -> ExportTable {
        let export_table_data = self.get_export_table_data();
        let export_table_offset = self.rva_to_offset(&export_table_data, export_table_data.export_directory.VirtualAddress);
        let export_table = unsafe { *(self.data.as_ptr().add(export_table_offset as usize).cast::<IMAGE_EXPORT_DIRECTORY>())};

        let names_offset = self.rva_to_offset(&export_table_data, export_table.AddressOfNames);
        let export_names = self.create_export_array(names_offset as usize, export_table.NumberOfNames, &export_table_data);

        let ordinals_offset = self.rva_to_offset(&export_table_data, export_table.AddressOfNameOrdinals);
        let export_ordinals = self.create_ordinals_array(ordinals_offset as usize, export_table.NumberOfFunctions, export_table.Base);

        ExportTable {array_of_names: export_names, array_of_ordinals: export_ordinals}
    }

    fn get_export_table_data(&self) -> ExportTableData {
        let section_count;
        let section_table_offset;
        let export_directory;

        if self.x64 {
            export_directory = self.nt_headers_x64.OptionalHeader.DataDirectory[0];
            section_count = self.nt_headers_x64.FileHeader.NumberOfSections;
            section_table_offset = std::mem::size_of::<u32>() + std::mem::size_of::<IMAGE_FILE_HEADER>() + self.nt_headers_x64.FileHeader.SizeOfOptionalHeader as usize;
        } else {
            export_directory = self.nt_headers_x86.OptionalHeader.DataDirectory[0];
            section_count = self.nt_headers_x86.FileHeader.NumberOfSections;
            section_table_offset = std::mem::size_of::<u32>() + std::mem::size_of::<IMAGE_FILE_HEADER>() + self.nt_headers_x86.FileHeader.SizeOfOptionalHeader as usize;
        }

        ExportTableData {section_count, section_table_offset, export_directory}
    }

    fn create_export_array(
        &self,
        names_array_offset: usize,
        number_of_names: u32,
        export_table_data: &ExportTableData,
    ) -> Vec<String> {
        (0..number_of_names)
            .map(|i| {
                let name_rva =
                    read_u32_le(&self.data, names_array_offset + (i as usize * 4));
                let name_offset = self.rva_to_offset(export_table_data, name_rva);
                self.parse_name(name_offset as usize)
            })
            .collect()
    }

    fn parse_name(&self, name_offset: usize) -> String {
        self.data[name_offset..]
            .iter()
            .take_while(|&&b| b != 0)
            .filter_map(|&b| char::from_u32(b as u32))
            .collect()
    }

    fn create_ordinals_array(
        &self,
        ordinals_array_offset: usize,
        function_count: u32,
        base: u32,
    ) -> Vec<u32> {
        (0..function_count)
            .map(|i| {
                let ordinal =
                    read_u16_le(&self.data, ordinals_array_offset + (i as usize * 2));
                ordinal as u32 + base
            })
            .collect()
    }

    fn rva_to_offset(&self, export_table_data: &ExportTableData, rva: u32) -> u32 {
        for i in 0..export_table_data.section_count {
            let section_header_offset = self.dos_header.e_lfanew as usize
                + export_table_data.section_table_offset
                + std::mem::size_of::<IMAGE_SECTION_HEADER>() * (i as usize);

            let section_header =
                unsafe { *(self.data.as_ptr().add(section_header_offset)
                    .cast::<IMAGE_SECTION_HEADER>()) };
            let end_of_header = section_header.VirtualAddress + section_header.SizeOfRawData;
            if end_of_header >= rva {
                return rva - section_header.VirtualAddress + section_header.PointerToRawData;
            }
        }

        panic!("Could not find section containing RVA {:#x}", rva);
    }
}
