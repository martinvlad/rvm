//! Push-style incremental Wasm module validation (ADR-160 §4).
//!
//! [`StreamingModuleValidator`] wraps `wasmparser` so a module can be checked
//! while it arrives, in arbitrary chunk splits, from bytes an upstream
//! verifier has already released. It never executes anything.
//!
//! * Every code-section entry is validated as soon as its bytes are complete;
//!   other sections are parsed whole (wasmparser needs them whole) and are
//!   bounded by [`ModulePolicy::max_section_bytes`].
//! * Imports are checked against the policy when the import section completes.
//! * Whole-module checks (function count equals code count, data count) run in
//!   [`StreamingModuleValidator::finish`].
//! * The buffer grows only with bytes actually received, never with a declared
//!   size, and a declared size beyond policy is refused before it is awaited.
//! * After any error the validator is poisoned, and `finish` cannot produce a
//!   [`ValidatedModule`].
//!
//! [`crate::validate_module`] remains the cheap framing pre-check; this is the
//! real validation.

use crate::module_policy::{
    ImportKind, ImportRef, Limit, ModuleError, ModulePolicy, UNBOUNDED_MEMORY_PAGES,
};
use alloc::string::ToString;
use alloc::vec::Vec;
use wasmparser::{
    BinaryReaderError, Chunk, Encoding, FuncValidatorAllocations, MemoryType, Parser, Payload,
    TypeRef, ValidPayload, Validator, WasmFeatures,
};

/// Slack for a section/body header (id byte plus a 5-byte LEB128 size).
const HEADER_SLACK: usize = 8;

/// The wasm feature set modules are validated against: WebAssembly 2.0
/// (reference types, bulk memory, multi-value, sign extension, saturating
/// conversions). Exceptions, threads, GC, memory64 and the component model are
/// off, so a tag section (id 13) is rejected here.
#[must_use]
pub fn wasm_features() -> WasmFeatures {
    WasmFeatures::WASM2
}

/// Where a streaming validation stands after a [`StreamingModuleValidator::push`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatorProgress {
    /// Bytes pushed so far.
    pub bytes_received: u64,
    /// Bytes the parser has consumed and validated.
    pub bytes_parsed: u64,
    /// Bytes held waiting for the rest of a section or function body.
    pub bytes_buffered: usize,
    /// Function bodies validated so far.
    pub functions_validated: u32,
    /// Whether the import section has been checked against the policy.
    pub imports_checked: bool,
}

/// A module that passed validation and the policy. Only
/// [`StreamingModuleValidator::finish`] constructs one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedModule {
    byte_len: u64,
    type_count: u32,
    import_count: u32,
    export_count: u32,
    function_count: u32,
}

impl ValidatedModule {
    /// Total module length in bytes.
    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }
    /// Entries in the type section.
    #[must_use]
    pub const fn type_count(&self) -> u32 {
        self.type_count
    }
    /// Imports declared.
    #[must_use]
    pub const fn import_count(&self) -> u32 {
        self.import_count
    }
    /// Exports declared.
    #[must_use]
    pub const fn export_count(&self) -> u32 {
        self.export_count
    }
    /// Functions defined (each with a validated body).
    #[must_use]
    pub const fn function_count(&self) -> u32 {
        self.function_count
    }
}

fn conv(e: &BinaryReaderError) -> ModuleError {
    ModuleError::Invalid {
        offset: e.offset(),
        message: e.message().to_string(),
    }
}

struct Run {
    consumed: usize,
    /// Extra bytes the parser says it needs beyond what it was given.
    need: u64,
    ended: bool,
}

/// Parser, validator and counters; everything except the byte buffer, so the
/// buffer can be borrowed while this is mutated.
struct Core {
    policy: ModulePolicy,
    parser: Parser,
    validator: Validator,
    allocs: Option<FuncValidatorAllocations>,
    consumed_total: u64,
    code_remaining: u32,
    functions_validated: u32,
    imports_checked: bool,
    types: u32,
    imports: u32,
    exports: u32,
    functions: u32,
}

impl Core {
    fn new(policy: ModulePolicy) -> Self {
        let features = wasm_features();
        let mut parser = Parser::new(0);
        parser.set_features(features);
        Self {
            policy,
            parser,
            validator: Validator::new_with_features(features),
            allocs: None,
            consumed_total: 0,
            code_remaining: 0,
            functions_validated: 0,
            imports_checked: false,
            types: 0,
            imports: 0,
            exports: 0,
            functions: 0,
        }
    }

    /// Largest number of bytes that may be buffered for the item the parser is
    /// working on.
    fn buffer_limit(&self) -> (usize, Limit) {
        if self.code_remaining > 0 {
            (
                self.policy
                    .max_function_body_bytes
                    .saturating_add(HEADER_SLACK),
                Limit::FunctionBodyBytes,
            )
        } else {
            (
                self.policy.max_section_bytes.saturating_add(HEADER_SLACK),
                Limit::SectionBytes,
            )
        }
    }

    fn run(&mut self, data: &[u8], eof: bool) -> Result<Run, ModuleError> {
        let mut pos = 0usize;
        loop {
            match self.parser.parse(&data[pos..], eof).map_err(|e| conv(&e))? {
                Chunk::NeedMoreData(need) => {
                    if eof {
                        return Err(ModuleError::Truncated);
                    }
                    return Ok(Run {
                        consumed: pos,
                        need,
                        ended: false,
                    });
                }
                Chunk::Parsed { consumed, payload } => {
                    let ended = self.handle(&payload)?;
                    pos += consumed;
                    self.consumed_total += consumed as u64;
                    if ended {
                        return Ok(Run {
                            consumed: pos,
                            need: 0,
                            ended: true,
                        });
                    }
                }
            }
        }
    }

    fn over(count: u32, max: u32, limit: Limit) -> Result<(), ModuleError> {
        if count > max {
            Err(ModuleError::LimitExceeded(limit))
        } else {
            Ok(())
        }
    }

    fn check_table(&self, initial: u64) -> Result<(), ModuleError> {
        if initial > self.policy.max_table_elements {
            return Err(ModuleError::LimitExceeded(Limit::TableElements));
        }
        Ok(())
    }

    fn check_memory(&self, m: &MemoryType) -> Result<(), ModuleError> {
        let effective = match m.maximum {
            Some(max) => max,
            None if m.memory64 => u64::MAX,
            None => UNBOUNDED_MEMORY_PAGES,
        };
        if effective > self.policy.max_memory_pages {
            return Err(ModuleError::LimitExceeded(Limit::MemoryPages));
        }
        Ok(())
    }

    /// Cheap count limits first, before wasmparser walks the section.
    fn precheck(&mut self, payload: &Payload<'_>) -> Result<(), ModuleError> {
        match payload {
            Payload::Version { encoding, .. } if *encoding != Encoding::Module => {
                return Err(ModuleError::NotACoreModule);
            }
            Payload::TypeSection(s) => {
                self.types = s.count();
                Self::over(self.types, self.policy.max_types, Limit::Types)?;
            }
            Payload::ImportSection(s) => {
                self.imports = s.count();
                Self::over(self.imports, self.policy.max_imports, Limit::Imports)?;
            }
            Payload::GlobalSection(s) => {
                Self::over(s.count(), self.policy.max_globals, Limit::Globals)?;
            }
            Payload::DataSection(s) => {
                Self::over(
                    s.count(),
                    self.policy.max_data_segments,
                    Limit::DataSegments,
                )?;
            }
            Payload::ElementSection(s) => {
                Self::over(
                    s.count(),
                    self.policy.max_element_segments,
                    Limit::ElementSegments,
                )?;
            }
            Payload::TableSection(s) => {
                for t in s.clone() {
                    let t = t.map_err(|e| conv(&e))?;
                    self.check_table(t.ty.initial)?;
                }
            }
            Payload::ExportSection(s) => {
                self.exports = s.count();
                Self::over(self.exports, self.policy.max_exports, Limit::Exports)?;
            }
            Payload::FunctionSection(s) => {
                self.functions = s.count();
                Self::over(self.functions, self.policy.max_functions, Limit::Functions)?;
            }
            Payload::CodeSectionStart { count, .. } => {
                Self::over(*count, self.policy.max_functions, Limit::Functions)?;
                self.code_remaining = *count;
            }
            Payload::CodeSectionEntry(body) => {
                self.code_remaining = self.code_remaining.saturating_sub(1);
                if body.range().len() > self.policy.max_function_body_bytes {
                    return Err(ModuleError::LimitExceeded(Limit::FunctionBodyBytes));
                }
                let mut total = 0u32;
                for run in body.get_locals_reader().map_err(|e| conv(&e))? {
                    let (n, _) = run.map_err(|e| conv(&e))?;
                    total = total.saturating_add(n);
                    Self::over(total, self.policy.max_locals, Limit::Locals)?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Returns `true` when the module has ended.
    fn handle(&mut self, payload: &Payload<'_>) -> Result<bool, ModuleError> {
        // Section size is enforced on the parsed section, so the verdict does
        // not depend on how the bytes were split. (Code is bounded per body.)
        if let Some((id, range)) = payload.as_section() {
            if id != 10 && range.len() > self.policy.max_section_bytes {
                return Err(ModuleError::LimitExceeded(Limit::SectionBytes));
            }
        }
        self.precheck(payload)?;

        match self.validator.payload(payload).map_err(|e| conv(&e))? {
            ValidPayload::Func(func, body) => {
                let mut v = func.into_validator(self.allocs.take().unwrap_or_default());
                let r = v.validate(&body);
                self.allocs = Some(v.into_allocations());
                r.map_err(|e| conv(&e))?;
                self.functions_validated += 1;
            }
            ValidPayload::End(_) => return Ok(true),
            ValidPayload::Ok | ValidPayload::Parser(_) => {}
        }

        // Content checks on sections wasmparser has now accepted.
        match payload {
            Payload::ImportSection(s) => {
                for (i, imp) in s.clone().into_iter().enumerate() {
                    let imp = imp.map_err(|e| conv(&e))?;
                    let kind = match &imp.ty {
                        TypeRef::Func(_) | TypeRef::FuncExact(_) => ImportKind::Func,
                        TypeRef::Table(t) => {
                            self.check_table(t.initial)?;
                            ImportKind::Table
                        }
                        TypeRef::Memory(m) => {
                            self.check_memory(m)?;
                            ImportKind::Memory
                        }
                        TypeRef::Global(_) => ImportKind::Global,
                        TypeRef::Tag(_) => ImportKind::Tag,
                    };
                    let r = ImportRef {
                        module: imp.module,
                        name: imp.name,
                        kind,
                    };
                    if !self.policy.imports.allows(&r) {
                        return Err(ModuleError::ForbiddenImport { index: i as u32 });
                    }
                }
                self.imports_checked = true;
            }
            Payload::MemorySection(s) => {
                for m in s.clone() {
                    self.check_memory(&m.map_err(|e| conv(&e))?)?;
                }
            }
            _ => {}
        }
        Ok(false)
    }
}

/// Validates a Wasm module from chunks pushed in any split.
pub struct StreamingModuleValidator {
    core: Core,
    buf: Vec<u8>,
    /// `buf.len()` at which parsing is worth retrying.
    need_len: usize,
    received: u64,
    failed: Option<ModuleError>,
}

impl StreamingModuleValidator {
    /// A validator enforcing `policy`.
    #[must_use]
    pub fn new(policy: ModulePolicy) -> Self {
        Self {
            core: Core::new(policy),
            buf: Vec::new(),
            need_len: 0,
            received: 0,
            failed: None,
        }
    }

    /// Feed the next chunk. Any split of the module, including one byte at a
    /// time, gives the same verdict. After an `Err` every later call returns
    /// the same error.
    pub fn push(&mut self, bytes: &[u8]) -> Result<ValidatorProgress, ModuleError> {
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        match self.push_inner(bytes) {
            Ok(()) => Ok(self.progress()),
            Err(e) => {
                self.failed = Some(e.clone());
                self.buf = Vec::new();
                Err(e)
            }
        }
    }

    fn progress(&self) -> ValidatorProgress {
        ValidatorProgress {
            bytes_received: self.received,
            bytes_parsed: self.core.consumed_total,
            bytes_buffered: self.buf.len(),
            functions_validated: self.core.functions_validated,
            imports_checked: self.core.imports_checked,
        }
    }

    /// Refuse a wait the policy would never allow, before buffering for it.
    fn check_wait(&self, remaining: usize, need: u64) -> Result<(), ModuleError> {
        let total = (remaining as u64).saturating_add(need);
        if self.core.consumed_total.saturating_add(total) > self.core.policy.max_module_bytes as u64
        {
            return Err(ModuleError::LimitExceeded(Limit::ModuleBytes));
        }
        let (limit, which) = self.core.buffer_limit();
        if total > limit as u64 {
            return Err(ModuleError::LimitExceeded(which));
        }
        Ok(())
    }

    fn push_inner(&mut self, mut input: &[u8]) -> Result<(), ModuleError> {
        let total = self.received.saturating_add(input.len() as u64);
        if total > self.core.policy.max_module_bytes as u64 {
            return Err(ModuleError::LimitExceeded(Limit::ModuleBytes));
        }
        self.received = total;

        while !input.is_empty() {
            if self.buf.is_empty() {
                // Parse straight from the caller's slice; copy only the tail.
                let run = self.core.run(input, false)?;
                input = &input[run.consumed..];
                if !input.is_empty() {
                    self.check_wait(input.len(), run.need)?;
                    self.need_len = input.len().saturating_add(run.need as usize);
                    self.buf.extend_from_slice(input);
                    input = &[];
                }
            } else {
                let want = self.need_len.saturating_sub(self.buf.len()).max(1);
                let take = want.min(input.len());
                self.buf.extend_from_slice(&input[..take]);
                input = &input[take..];
                if self.buf.len() < self.need_len {
                    continue;
                }
                let run = self.core.run(&self.buf, false)?;
                self.buf.drain(..run.consumed);
                self.check_wait(self.buf.len(), run.need)?;
                self.need_len = self.buf.len().saturating_add(run.need as usize);
            }
        }
        Ok(())
    }

    /// Signal end of input and run the whole-module checks.
    ///
    /// # Errors
    ///
    /// Any [`ModuleError`]; a rejected module yields no [`ValidatedModule`].
    pub fn finish(mut self) -> Result<ValidatedModule, ModuleError> {
        if let Some(e) = self.failed.take() {
            return Err(e);
        }
        let run = self.core.run(&self.buf, true)?;
        if !run.ended || run.consumed != self.buf.len() {
            return Err(ModuleError::Truncated);
        }
        Ok(ValidatedModule {
            byte_len: self.received,
            type_count: self.core.types,
            import_count: self.core.imports,
            export_count: self.core.exports,
            function_count: self.core.functions_validated,
        })
    }
}
