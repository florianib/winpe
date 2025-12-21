//! PE binary parsing logic

use windows::Win32::System::Diagnostics::Debug::{IMAGE_FILE_HEADER, IMAGE_SECTION_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64};
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE};

use crate::winpe::constants::*;
use crate::winpe::types::{ExportTable, ExportTableData, PE};
use crate::winpe::utils::{read_u32_le, read_u16_le};

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

impl PE {
    pub(crate) fn build(data: Vec<u8>) -> PE {
        let dos_header = unsafe { *data.as_ptr().cast::<IMAGE_DOS_HEADER>() };
        let bitness = unsafe {
            *(data
                .as_ptr()
                .add(dos_header.e_lfanew as usize + PE_MAGIC_OFFSET)
                .cast::<u16>())
        };

        let (nt_headers_x64, nt_headers_x86, x64) = if bitness == PE_MAGIC_X64 {
            let nt_headers_x64 = unsafe {
                *(data
                    .as_ptr()
                    .add(dos_header.e_lfanew as usize)
                    .cast::<IMAGE_NT_HEADERS64>())
            };
            (nt_headers_x64, Default::default(), true)
        } else if bitness == PE_MAGIC_X86 {
            let nt_headers_x86 = unsafe {
                *(data
                    .as_ptr()
                    .add(dos_header.e_lfanew as usize)
                    .cast::<IMAGE_NT_HEADERS32>())
            };
            (Default::default(), nt_headers_x86, false)
        } else {
            panic!("Unknown PE architecture: {:#x}", bitness);
        };

        let is_valid_dos = dos_header.e_magic == IMAGE_DOS_SIGNATURE;
        let is_valid_nt = if x64 {
            nt_headers_x64.Signature == IMAGE_NT_SIGNATURE
        } else {
            nt_headers_x86.Signature == IMAGE_NT_SIGNATURE
        };

        if !is_valid_dos || !is_valid_nt {
            panic!("Invalid PE binary file format");
        }

        let mut pe = PE::new(
            dos_header,
            x64,
            nt_headers_x64,
            nt_headers_x86,
            data,
        );

        let export_table = pe.create_export_table();
        *pe.get_export_table_mut() = export_table;

        pe
    }

    fn create_export_table(&self) -> ExportTable {
        let export_table_data = self.get_export_table_data();
        let export_table_offset = self.rva_to_file_offset(export_table_data.export_directory.VirtualAddress as usize);
        let export_table = unsafe {
            *(self.get_data().as_ptr().add(export_table_offset).cast::<IMAGE_EXPORT_DIRECTORY>())
        };

        let names_offset = self.rva_to_file_offset(export_table.AddressOfNames as usize);
        let export_names = self.create_export_array(names_offset, export_table.NumberOfNames, &export_table_data);

        let ordinals_offset = self.rva_to_file_offset(export_table.AddressOfNameOrdinals as usize);
        let export_ordinals = self.create_ordinals_array(ordinals_offset, export_table.NumberOfFunctions, export_table.Base);

        ExportTable {
            array_of_names: export_names,
            array_of_ordinals: export_ordinals,
        }
    }

    fn get_export_table_data(&self) -> ExportTableData {
        let (export_directory, section_count, section_table_offset) = if self.is_x64() {
            (
                self.get_nt_headers_x64().OptionalHeader.DataDirectory[0],
                self.get_nt_headers_x64().FileHeader.NumberOfSections,
                std::mem::size_of::<u32>()
                    + std::mem::size_of::<IMAGE_FILE_HEADER>()
                    + self.get_nt_headers_x64().FileHeader.SizeOfOptionalHeader as usize,
            )
        } else {
            (
                self.get_nt_headers_x86().OptionalHeader.DataDirectory[0],
                self.get_nt_headers_x86().FileHeader.NumberOfSections,
                std::mem::size_of::<u32>()
                    + std::mem::size_of::<IMAGE_FILE_HEADER>()
                    + self.get_nt_headers_x86().FileHeader.SizeOfOptionalHeader as usize,
            )
        };

        ExportTableData {
            section_count,
            section_table_offset,
            export_directory,
        }
    }

    fn create_export_array(
        &self,
        names_array_offset: usize,
        number_of_names: u32,
        _export_table_data: &ExportTableData,
    ) -> Vec<String> {
        let data = self.get_data();
        (0..number_of_names)
            .map(|i| {
                let name_rva = read_u32_le(data, names_array_offset + (i as usize * 4));
                let name_offset = self.rva_to_file_offset(name_rva as usize);
                self.parse_name(name_offset)
            })
            .collect()
    }

    fn parse_name(&self, name_offset: usize) -> String {
        self.get_data()[name_offset..]
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
        let data = self.get_data();
        (0..function_count)
            .map(|i| {
                let ordinal = read_u16_le(data, ordinals_array_offset + (i as usize * 2));
                ordinal as u32 + base
            })
            .collect()
    }

    /// Calculates the section table offset
    fn section_table_offset(&self) -> usize {
        if self.is_x64() {
            std::mem::size_of::<u32>()
                + std::mem::size_of::<IMAGE_FILE_HEADER>()
                + self.get_nt_headers_x64().FileHeader.SizeOfOptionalHeader as usize
        } else {
            std::mem::size_of::<u32>()
                + std::mem::size_of::<IMAGE_FILE_HEADER>()
                + self.get_nt_headers_x86().FileHeader.SizeOfOptionalHeader as usize
        }
    }

    /// Converts a Relative Virtual Address (RVA) to a file offset
    ///
    /// # Arguments
    /// * `rva` - The RVA to convert
    ///
    /// # Returns
    /// The file offset corresponding to the RVA
    ///
    /// # Panics
    /// Panics if the RVA cannot be found in any section
    pub fn rva_to_file_offset(&self, rva: usize) -> usize {
        let section_count = if self.is_x64() {
            self.get_nt_headers_x64().FileHeader.NumberOfSections
        } else {
            self.get_nt_headers_x86().FileHeader.NumberOfSections
        };

        let section_table_offset = self.section_table_offset();
        let dos_header = self.get_dos_header();
        let data = self.get_data();

        for i in 0..section_count {
            let section_header_offset = dos_header.e_lfanew as usize
                + section_table_offset
                + std::mem::size_of::<IMAGE_SECTION_HEADER>() * (i as usize);

            let section_header = unsafe {
                *(data.as_ptr().add(section_header_offset).cast::<IMAGE_SECTION_HEADER>())
            };
            let end_of_header = section_header.VirtualAddress as usize + section_header.SizeOfRawData as usize;
            if end_of_header >= rva {
                return rva - section_header.VirtualAddress as usize + section_header.PointerToRawData as usize;
            }
        }

        panic!("Could not find correct section!");
    }

    /// Finds a section header by its virtual address
    ///
    /// # Arguments
    /// * `virtual_address` - The virtual address to search for
    ///
    /// # Returns
    /// The IMAGE_SECTION_HEADER matching the virtual address
    ///
    /// # Panics
    /// Panics if no section with the given virtual address is found
    pub fn get_section_by_virtual_address(&self, virtual_address: u32) -> IMAGE_SECTION_HEADER {
        let section_count = if self.is_x64() {
            self.get_nt_headers_x64().FileHeader.NumberOfSections
        } else {
            self.get_nt_headers_x86().FileHeader.NumberOfSections
        };

        let section_table_offset = self.section_table_offset();
        let dos_header = self.get_dos_header();
        let data = self.get_data();

        for i in 0..section_count {
            let section_header_offset = dos_header.e_lfanew as usize
                + section_table_offset
                + std::mem::size_of::<IMAGE_SECTION_HEADER>() * (i as usize);

            let section_header = unsafe {
                *(data.as_ptr().add(section_header_offset).cast::<IMAGE_SECTION_HEADER>())
            };
            if virtual_address == section_header.VirtualAddress {
                return section_header;
            }
        }

        panic!("Could not find reloc section!");
    }

    /// Returns a pointer to the first section header in the PE file
    ///
    /// This pointer can be used to access all section headers by incrementing it.
    /// The number of sections is available in `nt_headers.FileHeader.NumberOfSections`.
    pub fn get_section_headers_ptr(&self) -> *const IMAGE_SECTION_HEADER {
        let dos_header = self.get_dos_header();
        let nt_headers = if self.is_x64() {
            self.get_nt_headers_x64()
        } else {
            // For x86, we need to cast from x32 to x64 reference
            // This is safe because we're just reading the FileHeader which is the same
            unsafe { std::mem::transmute(self.get_nt_headers_x86()) }
        };

        ((dos_header.e_lfanew as usize + std::mem::size_of::<u32>()
            + std::mem::size_of::<IMAGE_FILE_HEADER>()
            + nt_headers.FileHeader.SizeOfOptionalHeader as usize) as *const u8)
            as *const IMAGE_SECTION_HEADER
    }
}
