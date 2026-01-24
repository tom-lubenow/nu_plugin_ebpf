//! Symbol resolution for stack traces
//!
//! This module provides utilities for resolving instruction pointer addresses
//! to human-readable symbol names. Currently supports kernel symbols via
//! /proc/kallsyms.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::OnceLock;

/// A resolved symbol with its name and offset
#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    /// The symbol name (e.g., "do_sys_openat2")
    pub name: String,
    /// Offset within the symbol (how far into the function)
    pub offset: u64,
    /// The module name if applicable (e.g., "[kernel]", "libc.so")
    pub module: Option<String>,
}

/// Kernel symbol table loaded from /proc/kallsyms
pub struct KernelSymbols {
    /// Sorted list of (address, name) pairs for binary search
    symbols: Vec<(u64, String)>,
}

impl KernelSymbols {
    /// Load kernel symbols from /proc/kallsyms
    ///
    /// This requires readable /proc/kallsyms. On some systems, non-root users
    /// may see all addresses as 0 due to kernel.kptr_restrict sysctl.
    pub fn load() -> Result<Self, std::io::Error> {
        let file = File::open("/proc/kallsyms")?;
        let reader = BufReader::new(file);

        let mut symbols = Vec::new();
        for line in reader.lines() {
            let line = line?;
            // Format: "address type name [module]"
            // Example: "ffffffff81000000 T _text"
            let parts: Vec<&str> = line.splitn(4, ' ').collect();
            if parts.len() >= 3
                && let Ok(addr) = u64::from_str_radix(parts[0], 16)
                && addr != 0
            {
                // Skip zero addresses (restricted kallsyms)
                let name = parts[2].to_string();
                symbols.push((addr, name));
            }
        }

        // Sort by address for binary search
        symbols.sort_by_key(|(addr, _)| *addr);

        Ok(Self { symbols })
    }

    /// Resolve an address to a symbol name and offset
    ///
    /// Returns None if the address is before all known symbols.
    pub fn resolve(&self, addr: u64) -> Option<ResolvedSymbol> {
        if self.symbols.is_empty() {
            return None;
        }

        // Binary search for the largest address <= addr
        let idx = self.symbols.partition_point(|(a, _)| *a <= addr);
        if idx == 0 {
            // Address is before all symbols
            return None;
        }

        let (sym_addr, name) = &self.symbols[idx - 1];
        Some(ResolvedSymbol {
            name: name.clone(),
            offset: addr - sym_addr,
            module: Some("[kernel]".to_string()),
        })
    }

    /// Check if kernel symbols are available (non-zero addresses)
    pub fn is_available(&self) -> bool {
        !self.symbols.is_empty()
    }

    /// Get the number of loaded symbols
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Check if the symbol table is empty
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

/// Global cached kernel symbols (loaded once)
static KERNEL_SYMBOLS: OnceLock<Result<KernelSymbols, String>> = OnceLock::new();

/// Get the global kernel symbol table (loads on first access)
pub fn kernel_symbols() -> Result<&'static KernelSymbols, &'static str> {
    KERNEL_SYMBOLS
        .get_or_init(|| {
            KernelSymbols::load().map_err(|e| format!("Failed to load kernel symbols: {}", e))
        })
        .as_ref()
        .map_err(|s| s.as_str())
}

/// Symbolize a list of instruction pointer addresses
///
/// Returns a list of ResolvedSymbols for each address. If an address cannot
/// be resolved, a placeholder with the hex address is returned.
pub fn symbolize_kernel_stack(frames: &[u64]) -> Vec<ResolvedSymbol> {
    let ksyms = kernel_symbols();

    frames
        .iter()
        .map(|&addr| {
            if let Ok(syms) = ksyms
                && let Some(resolved) = syms.resolve(addr)
            {
                return resolved;
            }
            // Fallback: return hex address as the "name"
            ResolvedSymbol {
                name: format!("0x{:x}", addr),
                offset: 0,
                module: None,
            }
        })
        .collect()
}

/// Format a resolved symbol for display
///
/// Returns something like "do_sys_openat2+0x48 [kernel]"
pub fn format_symbol(sym: &ResolvedSymbol) -> String {
    let mut result = sym.name.clone();
    if sym.offset > 0 {
        result.push_str(&format!("+0x{:x}", sym.offset));
    }
    if let Some(ref module) = sym.module {
        result.push_str(&format!(" {}", module));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_symbol() {
        // This test requires /proc/kallsyms to be readable
        if let Ok(syms) = KernelSymbols::load() {
            if syms.is_available() {
                // Try to resolve the first symbol
                let first_addr = syms.symbols.first().map(|(a, _)| *a).unwrap_or(0);
                if first_addr != 0 {
                    let resolved = syms.resolve(first_addr);
                    assert!(resolved.is_some());
                    assert_eq!(resolved.as_ref().unwrap().offset, 0);
                }
            }
        }
    }

    #[test]
    fn test_format_symbol() {
        let sym = ResolvedSymbol {
            name: "do_sys_openat2".to_string(),
            offset: 0x48,
            module: Some("[kernel]".to_string()),
        };
        assert_eq!(format_symbol(&sym), "do_sys_openat2+0x48 [kernel]");

        let sym_no_offset = ResolvedSymbol {
            name: "do_sys_openat2".to_string(),
            offset: 0,
            module: Some("[kernel]".to_string()),
        };
        assert_eq!(format_symbol(&sym_no_offset), "do_sys_openat2 [kernel]");
    }
}
