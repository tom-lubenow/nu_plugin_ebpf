use super::*;

impl EbpfState {
    /// Helper to read all entries from an i64->i64 hash/per-CPU-hash map
    fn read_i64_hash_map(
        &self,
        id: u32,
        has_map: impl Fn(&ActiveProbe) -> bool,
        map_name: &str,
    ) -> Result<Vec<(i64, i64)>, LoadError> {
        let mut probes = self.probes.lock().map_err(|_| LoadError::LockPoisoned)?;
        let probe = probes.get_mut(&id).ok_or(LoadError::ProbeNotFound(id))?;

        if !has_map(probe) {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();

        if let Some(map) = probe.ebpf.map_mut(map_name) {
            if let Ok(hash_map) = AyaHashMap::<_, i64, i64>::try_from(&mut *map) {
                for (key, value) in hash_map.iter().filter_map(|item| item.ok()) {
                    entries.push((key, value));
                }
            } else if let Ok(per_cpu_hash_map) = PerCpuHashMap::<_, i64, i64>::try_from(&mut *map) {
                for (key, values) in per_cpu_hash_map.iter().filter_map(|item| item.ok()) {
                    let total = values.iter().copied().sum::<i64>();
                    entries.push((key, total));
                }
            } else {
                return Err(LoadError::MapNotFound(format!(
                    "Failed to convert {map_name} map as hash/per-cpu hash"
                )));
            }
        }

        // Warn if map is approaching capacity
        if entries.len() > MAP_CAPACITY_WARN_THRESHOLD {
            eprintln!(
                "Warning: map '{}' is {}% full ({}/{} entries). New entries may be dropped.",
                map_name,
                entries.len() * 100 / MAX_MAP_ENTRIES,
                entries.len(),
                MAX_MAP_ENTRIES
            );
        }

        Ok(entries)
    }

    /// Read all counter entries from a probe's counter map (integer keys)
    ///
    /// Supports both regular hash and per-CPU hash maps. Per-CPU values are
    /// aggregated to a single total per key.
    pub fn get_counters(&self, id: u32) -> Result<Vec<CounterEntry>, LoadError> {
        let entries = self.read_i64_hash_map(id, |p| p.has_counter_map, "counters")?;
        Ok(entries
            .into_iter()
            .map(|(key, count)| CounterEntry { key, count })
            .collect())
    }

    /// Read all counter entries from a probe's string counter map
    ///
    /// Supports both regular hash and per-CPU hash maps. Per-CPU values are
    /// aggregated to a single total per key.
    pub fn get_string_counters(&self, id: u32) -> Result<Vec<StringCounterEntry>, LoadError> {
        let mut probes = self.probes.lock().map_err(|_| LoadError::LockPoisoned)?;
        let probe = probes.get_mut(&id).ok_or(LoadError::ProbeNotFound(id))?;

        if !probe.has_string_counter_map {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();

        if let Some(map) = probe.ebpf.map_mut("str_counters") {
            // String counter map uses [u8; 16] as key (comm is 16 bytes)
            if let Ok(hash_map) = AyaHashMap::<_, [u8; 16], i64>::try_from(&mut *map) {
                for (key_bytes, count) in hash_map.iter().filter_map(|item| item.ok()) {
                    // Convert the key bytes to a string (null-terminated)
                    let key = std::str::from_utf8(&key_bytes)
                        .unwrap_or("")
                        .trim_end_matches('\0')
                        .to_string();
                    entries.push(StringCounterEntry { key, count });
                }
            } else if let Ok(per_cpu_hash_map) =
                PerCpuHashMap::<_, [u8; 16], i64>::try_from(&mut *map)
            {
                for (key_bytes, values) in per_cpu_hash_map.iter().filter_map(|item| item.ok()) {
                    let key = std::str::from_utf8(&key_bytes)
                        .unwrap_or("")
                        .trim_end_matches('\0')
                        .to_string();
                    let count = values.iter().copied().sum::<i64>();
                    entries.push(StringCounterEntry { key, count });
                }
            } else {
                return Err(LoadError::MapNotFound(
                    "Failed to convert str_counters map as hash/per-cpu hash".to_string(),
                ));
            }
        }

        // Warn if map is approaching capacity
        if entries.len() > MAP_CAPACITY_WARN_THRESHOLD {
            eprintln!(
                "Warning: map 'str_counters' is {}% full ({}/{} entries). New entries may be dropped.",
                entries.len() * 100 / MAX_MAP_ENTRIES,
                entries.len(),
                MAX_MAP_ENTRIES
            );
        }

        Ok(entries)
    }

    /// Read all histogram entries from a probe's histogram map
    ///
    /// Returns all bucket-count pairs from the bpf-histogram hash map,
    /// sorted by bucket number.
    pub fn get_histogram(&self, id: u32) -> Result<Vec<HistogramEntry>, LoadError> {
        let mut entries: Vec<HistogramEntry> = self
            .read_i64_hash_map(id, |p| p.has_histogram_map, "histogram")?
            .into_iter()
            .map(|(bucket, count)| HistogramEntry { bucket, count })
            .collect();

        // Sort by bucket for display
        entries.sort_by_key(|e| e.bucket);

        Ok(entries)
    }

    /// Read all kernel stack traces from a probe's stack trace map
    ///
    /// Returns all stack traces collected by $ctx.kstack.
    /// Each stack trace contains a unique ID and the instruction pointer addresses.
    pub fn get_kernel_stacks(&self, id: u32) -> Result<Vec<StackTrace>, LoadError> {
        self.get_stacks_from_map(id, "kstacks", |p| p.has_kstack_map)
    }

    /// Read all user stack traces from a probe's stack trace map
    ///
    /// Returns all stack traces collected by $ctx.ustack.
    /// Each stack trace contains a unique ID and the instruction pointer addresses.
    pub fn get_user_stacks(&self, id: u32) -> Result<Vec<StackTrace>, LoadError> {
        self.get_stacks_from_map(id, "ustacks", |p| p.has_ustack_map)
    }

    /// Helper to read stack traces from a named stack trace map
    fn get_stacks_from_map(
        &self,
        id: u32,
        map_name: &str,
        has_map: impl Fn(&ActiveProbe) -> bool,
    ) -> Result<Vec<StackTrace>, LoadError> {
        let mut probes = self.probes.lock().map_err(|_| LoadError::LockPoisoned)?;
        let probe = probes.get_mut(&id).ok_or(LoadError::ProbeNotFound(id))?;

        if !has_map(probe) {
            return Ok(Vec::new());
        }

        let mut stacks = Vec::new();

        if let Some(map) = probe.ebpf.map_mut(map_name) {
            // StackTraceMap is keyed by stack_id (u32) and contains arrays of u64 IPs
            let stack_map: aya::maps::StackTraceMap<_> = aya::maps::StackTraceMap::try_from(map)
                .map_err(|e| {
                    LoadError::MapNotFound(format!("Failed to access {}: {}", map_name, e))
                })?;

            for (stack_id, trace) in stack_map.iter().filter_map(|item| item.ok()) {
                // Extract instruction pointers from the trace, filtering zeros
                let frames: Vec<u64> = trace
                    .frames()
                    .iter()
                    .map(|f| f.ip)
                    .filter(|&ip| ip != 0)
                    .collect();

                if !frames.is_empty() {
                    stacks.push(StackTrace {
                        id: stack_id as i64,
                        frames,
                    });
                }
            }
        }

        Ok(stacks)
    }
}
