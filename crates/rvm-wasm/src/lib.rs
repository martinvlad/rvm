//! # RVM WebAssembly Guest Runtime
//!
//! Optional WebAssembly execution environment for RVM partitions.
//! When enabled, partitions can host Wasm modules as an alternative
//! to native AArch64/RISC-V/x86-64 guests.
//!
//! ## Design
//!
//! - Wasm modules execute in a sandboxed interpreter within a partition
//! - Host functions are exposed through the capability system
//! - All Wasm state transitions are witness-logged
//! - Agent lifecycle follows ADR-140 state machine
//! - Per-partition resource quotas are enforced per epoch
//! - Migration uses a 7-step protocol with DC-7 timeout
//!
//! This crate is a compile-time optional feature; disabling it
//! removes all Wasm-related code from the final binary.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::needless_range_loop,
    clippy::manual_flatten,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::new_without_default,
    clippy::explicit_iter_loop
)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod agent;
pub mod host_functions;
pub mod migration;
pub mod quota;

#[cfg(feature = "alloc")]
pub mod module_policy;
#[cfg(feature = "alloc")]
pub mod streaming;

#[cfg(feature = "alloc")]
pub use module_policy::{
    AllowedImport, ImportKind, ImportPolicy, ImportRef, Limit, ModuleError, ModulePolicy,
};
#[cfg(feature = "alloc")]
pub use streaming::{wasm_features, StreamingModuleValidator, ValidatedModule, ValidatorProgress};

use rvm_types::{PartitionId, RvmError, RvmResult};

/// Maximum Wasm module size in bytes (1 MiB default).
pub const MAX_MODULE_SIZE: usize = 1024 * 1024;

/// Status of a Wasm module within a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmModuleState {
    /// The module has been loaded but not yet validated.
    Loaded,
    /// The module has been validated and is ready to execute.
    Validated,
    /// The module is currently executing.
    Running,
    /// The module has been terminated.
    Terminated,
}

/// Metadata for a loaded Wasm module.
#[derive(Debug, Clone, Copy)]
pub struct WasmModuleInfo {
    /// The partition hosting this module.
    pub partition: PartitionId,
    /// Current module state.
    pub state: WasmModuleState,
    /// Size of the module in bytes.
    pub size_bytes: u32,
    /// Number of exported functions.
    pub export_count: u16,
    /// Number of imported (host) functions.
    pub import_count: u16,
}

/// Well-known Wasm section IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WasmSectionId {
    /// Custom section (name + opaque data).
    Custom = 0,
    /// Type section (function signatures).
    Type = 1,
    /// Import section.
    Import = 2,
    /// Function section (type indices).
    Function = 3,
    /// Table section.
    Table = 4,
    /// Memory section.
    Memory = 5,
    /// Global section.
    Global = 6,
    /// Export section.
    Export = 7,
    /// Start section.
    Start = 8,
    /// Element section.
    Element = 9,
    /// Code section.
    Code = 10,
    /// Data section.
    Data = 11,
    /// Data count section (bulk memory proposal).
    DataCount = 12,
    /// Tag section (exception-handling proposal). Framing only: the streaming
    /// validator rejects it unless the feature set enables exceptions.
    Tag = 13,
}

impl WasmSectionId {
    /// Position of this section in the binary format's required order. The
    /// numeric id is not that order: data count (12) precedes code (10) and
    /// data (11), and tag (13) sits between memory and global.
    #[must_use]
    pub const fn order_rank(self) -> u8 {
        match self {
            Self::Custom => 0,
            Self::Type => 1,
            Self::Import => 2,
            Self::Function => 3,
            Self::Table => 4,
            Self::Memory => 5,
            Self::Tag => 6,
            Self::Global => 7,
            Self::Export => 8,
            Self::Start => 9,
            Self::Element => 10,
            Self::DataCount => 11,
            Self::Code => 12,
            Self::Data => 13,
        }
    }

    /// Try to parse a section ID from a raw byte.
    #[must_use]
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Custom),
            1 => Some(Self::Type),
            2 => Some(Self::Import),
            3 => Some(Self::Function),
            4 => Some(Self::Table),
            5 => Some(Self::Memory),
            6 => Some(Self::Global),
            7 => Some(Self::Export),
            8 => Some(Self::Start),
            9 => Some(Self::Element),
            10 => Some(Self::Code),
            11 => Some(Self::Data),
            12 => Some(Self::DataCount),
            13 => Some(Self::Tag),
            _ => None,
        }
    }
}

/// Summary of validated Wasm sections found in a module.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct WasmValidationResult {
    /// Number of sections found.
    pub section_count: u16,
    /// Whether a Type section is present.
    pub has_type: bool,
    /// Whether a Function section is present.
    pub has_function: bool,
    /// Whether a Memory section is present.
    pub has_memory: bool,
    /// Whether an Export section is present.
    pub has_export: bool,
    /// Whether a Code section is present.
    pub has_code: bool,
    /// Total size of all section payloads in bytes.
    pub total_payload_bytes: u32,
}

/// Validate a Wasm module: header + section structure. **Cheap framing
/// pre-check only**: it does not parse section contents, validate function
/// bodies or apply policy. Use `StreamingModuleValidator` (feature `alloc`)
/// for real validation.
///
/// Checks:
/// 1. Magic number (`\0asm`) and version (1)
/// 2. Each section has a valid ID and its declared size fits within the module
/// 3. Non-custom sections appear in the binary format's order (see
///    [`WasmSectionId::order_rank`]; custom sections may appear anywhere)
/// 4. No duplicate non-custom sections
///
/// Returns a summary of the sections found.
pub fn validate_module(bytes: &[u8]) -> RvmResult<WasmValidationResult> {
    // Enforce maximum module size (DC-7 budget constraint).
    if bytes.len() > MAX_MODULE_SIZE {
        return Err(RvmError::ResourceLimitExceeded);
    }
    if bytes.len() < 8 {
        return Err(RvmError::ProofInvalid);
    }
    // Wasm magic: \0asm
    if bytes[0..4] != [0x00, 0x61, 0x73, 0x6D] {
        return Err(RvmError::ProofInvalid);
    }
    // Wasm version 1
    if bytes[4..8] != [0x01, 0x00, 0x00, 0x00] {
        return Err(RvmError::Unsupported);
    }

    let mut result = WasmValidationResult::default();
    let mut pos = 8;
    let mut last_non_custom_rank: Option<u8> = None;
    let mut seen_sections: u16 = 0; // bitmask for section IDs 0-13

    while pos < bytes.len() {
        // Read section ID.
        if pos >= bytes.len() {
            break;
        }
        let section_id_byte = bytes[pos];
        pos += 1;

        let section_id = WasmSectionId::from_u8(section_id_byte).ok_or(RvmError::ProofInvalid)?;

        // Read section size (LEB128 u32).
        let (section_size, bytes_read) = read_leb128_u32(bytes, pos)?;
        pos += bytes_read;

        // Verify section fits within module.
        if pos + section_size as usize > bytes.len() {
            return Err(RvmError::ProofInvalid);
        }

        // Enforce ordering: non-custom sections must be non-decreasing.
        if section_id != WasmSectionId::Custom {
            if let Some(last) = last_non_custom_rank {
                if section_id.order_rank() <= last {
                    return Err(RvmError::ProofInvalid);
                }
            }
            // Check for duplicates.
            let bit = 1u16 << section_id_byte;
            if seen_sections & bit != 0 {
                return Err(RvmError::ProofInvalid);
            }
            seen_sections |= bit;
            last_non_custom_rank = Some(section_id.order_rank());
        }

        // Track which sections are present.
        match section_id {
            WasmSectionId::Type => result.has_type = true,
            WasmSectionId::Function => result.has_function = true,
            WasmSectionId::Memory => result.has_memory = true,
            WasmSectionId::Export => result.has_export = true,
            WasmSectionId::Code => result.has_code = true,
            _ => {}
        }

        result.section_count += 1;
        result.total_payload_bytes = result.total_payload_bytes.saturating_add(section_size);

        // Skip section payload.
        pos += section_size as usize;
    }

    Ok(result)
}

/// Backward-compatible header-only validation.
pub fn validate_header(bytes: &[u8]) -> RvmResult<()> {
    validate_module(bytes).map(|_| ())
}

/// Read a LEB128-encoded u32 from `bytes` starting at `pos`.
///
/// Returns (value, bytes_consumed). Max 5 bytes for u32 LEB128.
/// Rejects non-canonical (over-long) encodings: on the 5th byte,
/// only the low 4 bits may be set (bits 28..31 of the u32).
fn read_leb128_u32(bytes: &[u8], start: usize) -> RvmResult<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    let mut pos = start;

    for i in 0u8..5 {
        if pos >= bytes.len() {
            return Err(RvmError::ProofInvalid);
        }
        let byte = bytes[pos];
        pos += 1;

        // On the 5th byte (i == 4), only the low 4 bits are valid for
        // a u32 (bits 28..31). Reject non-canonical over-long encodings
        // where higher bits are set.
        if i == 4 && byte > 0x0F {
            return Err(RvmError::ProofInvalid);
        }

        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, pos - start));
        }
        shift += 7;
    }
    // More than 5 bytes for a u32 — invalid.
    Err(RvmError::ProofInvalid)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec;

    /// Minimal valid Wasm module: magic + version, no sections.
    fn minimal_wasm() -> [u8; 8] {
        [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]
    }

    #[test]
    fn test_validate_module_rejects_oversized() {
        // Create a module that exceeds MAX_MODULE_SIZE.
        let mut bytes = vec![0u8; MAX_MODULE_SIZE + 1];
        // Set valid header so we know it's the size check that fires.
        bytes[..8].copy_from_slice(&minimal_wasm());
        assert_eq!(
            validate_module(&bytes),
            Err(RvmError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn test_validate_module_accepts_at_limit() {
        // A module of exactly MAX_MODULE_SIZE that is just a valid header
        // followed by a single Custom section spanning the remainder.
        let mut bytes = vec![0u8; MAX_MODULE_SIZE];
        bytes[..8].copy_from_slice(&minimal_wasm());

        // Custom section: id=0, then LEB128 size of remaining payload.
        // Remaining after header(8) + section_id(1) + size_bytes = MAX - 8.
        // The payload size is MAX - 8 - 1 - len(leb128).
        // For MAX_MODULE_SIZE = 1048576, payload = 1048576 - 8 - 1 - 3 = 1048564
        // LEB128 of 1048564 (0x0FFF74): [0xF4, 0xFE, 0x3F]
        let payload_size: u32 = (MAX_MODULE_SIZE - 8 - 1 - 3) as u32;
        bytes[8] = 0x00; // Custom section ID
        bytes[9] = (payload_size & 0x7F) as u8 | 0x80;
        bytes[10] = ((payload_size >> 7) & 0x7F) as u8 | 0x80;
        bytes[11] = ((payload_size >> 14) & 0x7F) as u8;

        let result = validate_module(&bytes);
        // Should pass the size check. The Custom section is valid (zeroed payload).
        assert!(result.is_ok());
    }

    fn with_sections(ids: &[u8]) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec::Vec::from(minimal_wasm());
        for id in ids {
            v.extend_from_slice(&[*id, 0x00]);
        }
        v
    }

    #[test]
    fn test_data_count_before_code_is_valid_order() {
        // Binary order: ... element(9), data count(12), code(10), data(11).
        assert!(validate_module(&with_sections(&[9, 12, 10, 11])).is_ok());
        assert!(validate_module(&with_sections(&[10, 12])).is_err());
    }

    #[test]
    fn test_tag_section_framing_and_order() {
        // Tag (13) sits between memory (5) and global (6).
        assert!(validate_module(&with_sections(&[5, 13, 6])).is_ok());
        assert!(validate_module(&with_sections(&[6, 13])).is_err());
        assert!(validate_module(&with_sections(&[13, 13])).is_err());
        assert_eq!(WasmSectionId::from_u8(13), Some(WasmSectionId::Tag));
        assert_eq!(WasmSectionId::from_u8(14), None);
    }

    #[test]
    fn test_validate_module_minimal_valid() {
        let bytes = minimal_wasm();
        let result = validate_module(&bytes).unwrap();
        assert_eq!(result.section_count, 0);
    }
}
