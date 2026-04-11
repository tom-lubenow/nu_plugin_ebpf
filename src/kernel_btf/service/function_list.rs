use std::fs;

use super::{FunctionCheckResult, FunctionListResult, KernelBtf};

impl KernelBtf {
    /// Find the available_filter_functions file
    pub(super) fn find_available_filter_functions() -> Option<String> {
        let paths = [
            "/sys/kernel/tracing/available_filter_functions",
            "/sys/kernel/debug/tracing/available_filter_functions",
        ];

        for path in paths {
            if std::path::Path::new(path).is_file() {
                return Some(path.to_string());
            }
        }

        None
    }

    /// Check if function validation is available
    pub fn has_function_list(&self) -> bool {
        self.available_filter_functions_path.is_some()
    }

    /// Load the list of available kernel functions (lazy, cached)
    fn load_function_list(&self) -> FunctionListResult {
        // Check if already loaded
        {
            let cache = self.function_cache.read().unwrap();
            if let Some(ref result) = *cache {
                return result.clone();
            }
        }

        // Load from file
        let result = self.read_available_functions();

        // Cache the result
        {
            let mut cache = self.function_cache.write().unwrap();
            *cache = Some(result.clone());
        }

        result
    }

    /// Read available functions from tracefs
    fn read_available_functions(&self) -> FunctionListResult {
        let path = match &self.available_filter_functions_path {
            Some(p) => p,
            None => return FunctionListResult::NotAvailable,
        };

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                return if e.kind() == std::io::ErrorKind::PermissionDenied {
                    FunctionListResult::PermissionDenied
                } else {
                    FunctionListResult::NotAvailable
                };
            }
        };

        // Each line is a function name, possibly with module info like "func_name [module]"
        // We extract just the function name
        let funcs = content
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() {
                    return None;
                }
                // Handle "func_name [module]" format
                let func_name = line.split_whitespace().next()?;
                Some(func_name.to_string())
            })
            .collect();

        FunctionListResult::Loaded(funcs)
    }

    /// Check if a kernel function exists and can be probed
    ///
    /// Returns a FunctionCheckResult indicating whether the function exists,
    /// doesn't exist (with suggestions), or validation is not possible.
    pub fn check_function(&self, name: &str) -> FunctionCheckResult {
        if self.available_filter_functions_path.is_none() {
            return FunctionCheckResult::CannotValidate;
        }

        match self.load_function_list() {
            // If we can't read tracefs due to permissions, skip validation.
            // The actual BPF loading will fail with a proper error if the function doesn't exist.
            // This allows CAP_BPF/CAP_PERFMON to work without also needing tracefs read access.
            FunctionListResult::PermissionDenied => FunctionCheckResult::CannotValidate,
            FunctionListResult::NotAvailable => FunctionCheckResult::CannotValidate,
            FunctionListResult::Loaded(ref funcs) if funcs.is_empty() => {
                // Empty file - can't validate
                FunctionCheckResult::CannotValidate
            }
            FunctionListResult::Loaded(ref funcs) => {
                if funcs.iter().any(|f| f == name) {
                    FunctionCheckResult::Exists
                } else {
                    let suggestions = self.find_similar_functions(funcs, name, 3);
                    FunctionCheckResult::NotFound { suggestions }
                }
            }
        }
    }

    /// Find similar function names using edit distance
    fn find_similar_functions(&self, funcs: &[String], name: &str, max: usize) -> Vec<String> {
        let mut candidates: Vec<(String, usize)> = funcs
            .iter()
            .filter_map(|f| {
                let dist = Self::edit_distance(name, f);
                // Only consider functions within a reasonable edit distance
                // Allow more distance for longer function names
                let max_dist = (name.len() / 3).clamp(2, 5);
                if dist <= max_dist {
                    Some((f.clone(), dist))
                } else {
                    None
                }
            })
            .collect();

        // Sort by edit distance (closest first)
        candidates.sort_by_key(|(_, dist)| *dist);

        // Return top N
        candidates
            .into_iter()
            .take(max)
            .map(|(name, _)| name)
            .collect()
    }

    /// Calculate Levenshtein edit distance between two strings
    pub(super) fn edit_distance(a: &str, b: &str) -> usize {
        let a_chars: Vec<char> = a.chars().collect();
        let b_chars: Vec<char> = b.chars().collect();
        let a_len = a_chars.len();
        let b_len = b_chars.len();

        if a_len == 0 {
            return b_len;
        }
        if b_len == 0 {
            return a_len;
        }

        // Use two rows instead of full matrix for memory efficiency
        let mut prev_row: Vec<usize> = (0..=b_len).collect();
        let mut curr_row: Vec<usize> = vec![0; b_len + 1];

        for (i, a_char) in a_chars.iter().enumerate() {
            curr_row[0] = i + 1;

            for (j, b_char) in b_chars.iter().enumerate() {
                let cost = if a_char == b_char { 0 } else { 1 };
                curr_row[j + 1] = (prev_row[j + 1] + 1) // deletion
                    .min(curr_row[j] + 1) // insertion
                    .min(prev_row[j] + cost); // substitution
            }

            std::mem::swap(&mut prev_row, &mut curr_row);
        }

        prev_row[b_len]
    }
}
