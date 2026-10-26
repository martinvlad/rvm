//! Policy and error types for incremental Wasm module validation (ADR-160 §4).
//!
//! A [`ModulePolicy`] is the set of limits a module must stay within. It is
//! meant to be derived from signed policy; the defaults are conservative
//! backstops, not the mechanism. Every limit is enforced *before* memory is
//! committed to the thing it limits.

use crate::MAX_MODULE_SIZE;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use rvm_types::RvmError;

/// A wasm page is 64 KiB; a 32-bit memory without a declared maximum may grow
/// to this many pages.
pub const UNBOUNDED_MEMORY_PAGES: u64 = 65_536;

/// Which policy limit a module exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// Total module bytes.
    ModuleBytes,
    /// Bytes of one non-code section (including custom sections).
    SectionBytes,
    /// Bytes of one function body.
    FunctionBodyBytes,
    /// Declared locals in one function.
    Locals,
    /// Entries in the type section.
    Types,
    /// Entries in the import section.
    Imports,
    /// Entries in the export section.
    Exports,
    /// Entries in the function section (and so in the code section).
    Functions,
    /// Memory pages (declared maximum, or 65 536 when none is declared).
    MemoryPages,
}

/// Kind of an imported item, as seen by an import predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportKind {
    /// A function.
    Func,
    /// A table.
    Table,
    /// A linear memory.
    Memory,
    /// A global.
    Global,
    /// An exception tag.
    Tag,
}

/// One import as presented to the policy. Borrowed from the section being
/// checked; never stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportRef<'a> {
    /// Import module name.
    pub module: &'a str,
    /// Import field name.
    pub name: &'a str,
    /// What is being imported.
    pub kind: ImportKind,
}

/// One allowlist entry. `name == None` allows every field of `module`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedImport {
    /// Module name that must match exactly.
    pub module: String,
    /// Field name that must match exactly, or `None` for any field.
    pub name: Option<String>,
}

/// Which imports a module may declare. Checked as soon as the import section
/// completes, so a forbidden import is refused before any later byte is
/// parsed (capability reconciliation hook, ADR-160 §4).
#[derive(Debug, Clone)]
pub enum ImportPolicy {
    /// Any import.
    AllowAll,
    /// No imports at all.
    DenyAll,
    /// Only imports matching an entry.
    Allowlist(Vec<AllowedImport>),
    /// Only imports for which the predicate returns `true`.
    Predicate(fn(&ImportRef<'_>) -> bool),
}

impl ImportPolicy {
    /// Whether `import` is permitted.
    #[must_use]
    pub fn allows(&self, import: &ImportRef<'_>) -> bool {
        match self {
            Self::AllowAll => true,
            Self::DenyAll => false,
            Self::Allowlist(list) => list.iter().any(|a| {
                a.module == import.module && a.name.as_deref().map_or(true, |n| n == import.name)
            }),
            Self::Predicate(f) => f(import),
        }
    }
}

/// Limits a module must satisfy to be accepted.
#[derive(Debug, Clone)]
pub struct ModulePolicy {
    /// Total module size. Default: [`MAX_MODULE_SIZE`], the ADR-155 backstop.
    pub max_module_bytes: usize,
    /// Largest non-code section that may be buffered. Non-code sections are
    /// parsed whole, so this bounds the validator's buffer.
    pub max_section_bytes: usize,
    /// Largest single function body.
    pub max_function_body_bytes: usize,
    /// Most locals (sum of run lengths) in one function.
    pub max_locals: u32,
    /// Most type-section entries.
    pub max_types: u32,
    /// Most imports.
    pub max_imports: u32,
    /// Most exports.
    pub max_exports: u32,
    /// Most defined functions.
    pub max_functions: u32,
    /// Largest memory, in 64 KiB pages. A memory with no declared maximum
    /// counts as [`UNBOUNDED_MEMORY_PAGES`].
    pub max_memory_pages: u64,
    /// Which imports are allowed.
    pub imports: ImportPolicy,
}

impl Default for ModulePolicy {
    /// Conservative backstop limits: 1 MiB module, 64 MiB of memory, no
    /// import beyond what the caller allows (`DenyAll`).
    fn default() -> Self {
        Self {
            max_module_bytes: MAX_MODULE_SIZE,
            max_section_bytes: MAX_MODULE_SIZE,
            max_function_body_bytes: 256 * 1024,
            max_locals: 4096,
            max_types: 10_000,
            max_imports: 1_024,
            max_exports: 1_024,
            max_functions: 50_000,
            max_memory_pages: 1_024,
            imports: ImportPolicy::DenyAll,
        }
    }
}

impl ModulePolicy {
    /// A policy that adds nothing to wasmparser's own validation: used to show
    /// that streaming and whole-buffer validation agree. Not for production.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            max_module_bytes: usize::MAX,
            max_section_bytes: usize::MAX,
            max_function_body_bytes: usize::MAX,
            max_locals: u32::MAX,
            max_types: u32::MAX,
            max_imports: u32::MAX,
            max_exports: u32::MAX,
            max_functions: u32::MAX,
            max_memory_pages: u64::MAX,
            imports: ImportPolicy::AllowAll,
        }
    }
}

/// Why a module was refused. After any error the validator is poisoned and no
/// [`crate::ValidatedModule`] can be produced from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleError {
    /// wasmparser rejected the bytes: malformed or invalid.
    Invalid {
        /// Byte offset of the problem within the module.
        offset: usize,
        /// wasmparser's message.
        message: String,
    },
    /// The stream ended before the module was complete.
    Truncated,
    /// A policy limit was exceeded.
    LimitExceeded(Limit),
    /// An import is not allowed by the policy. `index` is its position in the
    /// import section.
    ForbiddenImport {
        /// Zero-based position in the import section.
        index: u32,
    },
    /// The bytes encode a component, not a core module.
    NotACoreModule,
}

impl fmt::Display for ModuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid { offset, message } => {
                write!(f, "invalid wasm at offset {offset}: {message}")
            }
            Self::Truncated => f.write_str("wasm stream ended before the module was complete"),
            Self::LimitExceeded(l) => write!(f, "module exceeds policy limit {l:?}"),
            Self::ForbiddenImport { index } => {
                write!(f, "import {index} is not allowed by policy")
            }
            Self::NotACoreModule => f.write_str("bytes are not a core wasm module"),
        }
    }
}

impl From<ModuleError> for RvmError {
    fn from(e: ModuleError) -> Self {
        match e {
            ModuleError::LimitExceeded(_) => RvmError::ResourceLimitExceeded,
            ModuleError::ForbiddenImport { .. } => RvmError::InsufficientCapability,
            ModuleError::NotACoreModule => RvmError::Unsupported,
            ModuleError::Invalid { .. } | ModuleError::Truncated => RvmError::ProofInvalid,
        }
    }
}
