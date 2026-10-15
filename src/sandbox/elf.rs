//! Just enough ELF parsing to answer two questions about a binary before we
//! copy it into a Linux container: which CPU is it for, and is it statically
//! linked (so it runs in images without a C library, such as distroless or
//! scratch)?
//!
//! Only 64-bit little-endian ELF is recognised, which covers both targets we
//! build for (x86_64 and aarch64). Everything else is "not a Linux binary".

use std::io::Read;
use std::path::Path;

/// CPU architectures we ship static Linux builds for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// The `uname -m` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        }
    }

    /// The Rust target to build a static binary for this architecture.
    pub fn musl_target(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64-unknown-linux-musl",
            Arch::Aarch64 => "aarch64-unknown-linux-musl",
        }
    }

    /// Parses `uname -m` or Go/Docker/Kubernetes names (`amd64`, `arm64`).
    pub fn parse(name: &str) -> Option<Arch> {
        match name.trim().to_ascii_lowercase().as_str() {
            "x86_64" | "amd64" | "x86-64" => Some(Arch::X86_64),
            "aarch64" | "arm64" | "arm64v8" => Some(Arch::Aarch64),
            _ => None,
        }
    }
}

/// What we learned from an ELF header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfInfo {
    /// `None` for an ELF binary of another architecture.
    pub arch: Option<Arch>,
    /// No program interpreter (`PT_INTERP`): it needs no dynamic loader or libc.
    pub is_static: bool,
}

/// Program headers sit right after the 64-byte ELF header in practice, so
/// the first 64 KiB is plenty.
const HEAD_BYTES: u64 = 64 * 1024;

const PT_INTERP: u32 = 3;
const EM_X86_64: u16 = 0x3e;
const EM_AARCH64: u16 = 0xb7;

/// Reads the start of `path` and inspects it. `None` if it is not a 64-bit
/// little-endian ELF file (for example a macOS binary), or cannot be read.
pub fn inspect_file(path: &Path) -> Option<ElfInfo> {
    let mut head = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(HEAD_BYTES)
        .read_to_end(&mut head)
        .ok()?;
    inspect(&head)
}

/// Inspects the first bytes of a file.
pub fn inspect(bytes: &[u8]) -> Option<ElfInfo> {
    // Magic, then class 2 (64-bit) and data 1 (little-endian).
    if bytes.get(0..4)? != b"\x7fELF" || bytes.get(4)? != &2 || bytes.get(5)? != &1 {
        return None;
    }
    let arch = match u16_at(bytes, 18)? {
        EM_X86_64 => Some(Arch::X86_64),
        EM_AARCH64 => Some(Arch::Aarch64),
        _ => None,
    };
    let ph_offset = u64_at(bytes, 0x20)? as usize;
    let ph_size = u16_at(bytes, 0x36)? as usize;
    let ph_count = u16_at(bytes, 0x38)? as usize;
    let mut is_static = true;
    for i in 0..ph_count {
        // A header we cannot see in the bytes we read: assume dynamic, the
        // cautious answer (it only produces a warning).
        let Some(kind) = u32_at(bytes, ph_offset + i * ph_size) else {
            is_static = false;
            break;
        };
        if kind == PT_INTERP {
            is_static = false;
        }
    }
    Some(ElfInfo { arch, is_static })
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal 64-bit little-endian ELF header with program headers of the
    /// given types.
    fn fake_elf(machine: u16, program_header_types: &[u32]) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[18..20].copy_from_slice(&machine.to_le_bytes());
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        b[0x38..0x3a].copy_from_slice(&(program_header_types.len() as u16).to_le_bytes());
        for kind in program_header_types {
            let mut ph = vec![0u8; 56];
            ph[0..4].copy_from_slice(&kind.to_le_bytes());
            b.extend(ph);
        }
        b
    }

    #[test]
    fn static_and_dynamic() {
        let s = inspect(&fake_elf(EM_X86_64, &[1, 1])).unwrap();
        assert_eq!(s.arch, Some(Arch::X86_64));
        assert!(s.is_static);
        let d = inspect(&fake_elf(EM_AARCH64, &[6, PT_INTERP, 1])).unwrap();
        assert_eq!(d.arch, Some(Arch::Aarch64));
        assert!(!d.is_static);
    }

    #[test]
    fn other_architectures_and_formats() {
        // RISC-V: an ELF we have no build for.
        assert_eq!(inspect(&fake_elf(0xf3, &[])).unwrap().arch, None);
        // Mach-O 64-bit magic.
        assert_eq!(inspect(&[0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1]), None);
        assert_eq!(inspect(b"#!/bin/sh\n"), None);
        assert_eq!(inspect(&[]), None);
    }

    #[test]
    fn truncated_program_headers_count_as_dynamic() {
        let mut b = fake_elf(EM_X86_64, &[1]);
        b.truncate(66); // cuts the first program header's type in half
        assert!(!inspect(&b).unwrap().is_static);
    }

    #[test]
    fn arch_names() {
        assert_eq!(Arch::parse("amd64\n"), Some(Arch::X86_64));
        assert_eq!(Arch::parse("arm64"), Some(Arch::Aarch64));
        assert_eq!(Arch::parse("aarch64"), Some(Arch::Aarch64));
        assert_eq!(Arch::parse("armv7l"), None);
    }
}
