use super::*;
use crate::compiler::CounterKeySchema;
use aya::maps::{Map as AyaMap, MapData as AyaMapData};
use aya::util::nr_cpus;
use aya_obj::generated::{bpf_attr, bpf_cmd};
use std::io;
use std::mem;
use std::os::fd::{AsFd as _, AsRawFd as _};

fn hash_map_data(map: &mut AyaMap) -> Option<(&mut AyaMapData, bool)> {
    match map {
        AyaMap::HashMap(data) | AyaMap::LruHashMap(data) => Some((data, false)),
        AyaMap::PerCpuHashMap(data) | AyaMap::PerCpuLruHashMap(data) => Some((data, true)),
        _ => None,
    }
}

fn sys_bpf(cmd: bpf_cmd, attr: &mut bpf_attr) -> io::Result<i64> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd as u32,
            attr as *mut _ as *mut libc::c_void,
            mem::size_of::<bpf_attr>(),
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as i64)
    }
}

fn raw_bpf_map_get_next_key(
    fd: std::os::fd::BorrowedFd<'_>,
    key: Option<&[u8]>,
    next_key: &mut [u8],
) -> io::Result<bool> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    if let Some(key) = key {
        u.key = key.as_ptr() as u64;
    }
    u.__bindgen_anon_1.next_key = next_key.as_mut_ptr() as u64;

    match sys_bpf(bpf_cmd::BPF_MAP_GET_NEXT_KEY, &mut attr) {
        Ok(_) => Ok(true),
        Err(err) if err.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(err) => Err(err),
    }
}

fn raw_bpf_map_lookup_elem(
    fd: std::os::fd::BorrowedFd<'_>,
    key: &[u8],
    value: &mut [u8],
) -> io::Result<bool> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    u.key = key.as_ptr() as u64;
    u.__bindgen_anon_1.value = value.as_mut_ptr() as u64;
    u.flags = 0;

    match sys_bpf(bpf_cmd::BPF_MAP_LOOKUP_ELEM, &mut attr) {
        Ok(_) => Ok(true),
        Err(err) if err.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(err) => Err(err),
    }
}

fn decode_i64_le(buf: &[u8]) -> i64 {
    let mut bytes = [0u8; 8];
    let copy_len = buf.len().min(8);
    bytes[..copy_len].copy_from_slice(&buf[..copy_len]);
    i64::from_le_bytes(bytes)
}

fn decode_scalar_le(buf: &[u8], size: usize, signed: bool) -> i64 {
    let mut bytes = [0u8; 8];
    let copy_len = buf.len().min(size).min(8);
    bytes[..copy_len].copy_from_slice(&buf[..copy_len]);
    if signed && copy_len == size.min(8) && copy_len > 0 && (bytes[copy_len - 1] & 0x80) != 0 {
        bytes[copy_len..].fill(0xff);
    }
    i64::from_le_bytes(bytes)
}

fn decode_bitfield_le(
    buf: &[u8],
    size: usize,
    signed: bool,
    bitfield: crate::compiler::mir::BitfieldInfo,
) -> i64 {
    if size == 0 || bitfield.bit_size == 0 {
        return 0;
    }

    let storage = decode_scalar_le(buf, size, false) as u64;
    let storage_bits = (size.min(8) * 8) as u32;
    if bitfield.bit_offset >= storage_bits || bitfield.bit_size > storage_bits {
        return 0;
    }
    let end = match bitfield.bit_offset.checked_add(bitfield.bit_size) {
        Some(end) if end <= storage_bits => end,
        _ => return 0,
    };
    let value = if bitfield.bit_size == 64 {
        storage >> bitfield.bit_offset
    } else {
        let mask = (1u64 << bitfield.bit_size) - 1;
        (storage >> bitfield.bit_offset) & mask
    };
    if !signed || end == 64 {
        value as i64
    } else {
        let shift = 64 - bitfield.bit_size;
        ((value << shift) as i64) >> shift
    }
}

fn decode_fixed_string(buf: &[u8], size: usize) -> String {
    let max_len = buf.len().min(size);
    let null_pos = buf[..max_len]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(max_len);
    String::from_utf8_lossy(&buf[..null_pos]).to_string()
}

impl EbpfState {
    pub(super) fn deserialize_bytes_counter_key(
        buf: &[u8],
        schema: Option<&CounterKeySchema>,
    ) -> CounterKeyValue {
        match schema {
            Some(schema) => Self::deserialize_bytes_counter_key_with_schema(buf, schema),
            None => CounterKeyValue::Bytes(buf.to_vec()),
        }
    }

    fn deserialize_bytes_counter_key_with_schema(
        buf: &[u8],
        schema: &CounterKeySchema,
    ) -> CounterKeyValue {
        match schema {
            CounterKeySchema::Int { size, signed } => {
                CounterKeyValue::Int(decode_scalar_le(buf, *size, *signed))
            }
            CounterKeySchema::String { size } => {
                CounterKeyValue::String(decode_fixed_string(buf, *size))
            }
            CounterKeySchema::Bytes { size } => {
                CounterKeyValue::Bytes(buf[..buf.len().min(*size)].to_vec())
            }
            CounterKeySchema::Array { elem, len } => {
                let elem_size = elem.size().max(1);
                let mut values = Vec::with_capacity(*len);
                for idx in 0..*len {
                    let start = idx * elem_size;
                    let end = start.saturating_add(elem_size).min(buf.len());
                    let elem_buf = if start < buf.len() {
                        &buf[start..end]
                    } else {
                        &[]
                    };
                    values.push(Self::deserialize_bytes_counter_key_with_schema(
                        elem_buf, elem,
                    ));
                }
                CounterKeyValue::Array(values)
            }
            CounterKeySchema::Record { fields, .. } => {
                let mut values = Vec::with_capacity(fields.len());
                for field in fields {
                    let end = field
                        .offset
                        .saturating_add(field.schema.size())
                        .min(buf.len());
                    let field_buf = if field.offset < buf.len() {
                        &buf[field.offset..end]
                    } else {
                        &[]
                    };
                    let value = match (&field.schema, field.bitfield) {
                        (CounterKeySchema::Int { size, signed }, Some(bitfield)) => {
                            CounterKeyValue::Int(decode_bitfield_le(
                                field_buf, *size, *signed, bitfield,
                            ))
                        }
                        _ => Self::deserialize_bytes_counter_key_with_schema(
                            field_buf,
                            &field.schema,
                        ),
                    };
                    values.push((field.name.clone(), value));
                }
                CounterKeyValue::Record(values)
            }
        }
    }

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

    /// Read all counter entries from a probe's bytes counter map.
    ///
    /// Supports both regular hash and per-CPU hash maps. Per-CPU values are
    /// aggregated to a single total per key.
    pub fn get_bytes_counters(&self, id: u32) -> Result<Vec<BytesCounterEntry>, LoadError> {
        let mut probes = self.probes.lock().map_err(|_| LoadError::LockPoisoned)?;
        let probe = probes.get_mut(&id).ok_or(LoadError::ProbeNotFound(id))?;

        if !probe.has_bytes_counter_map {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let key_schema = probe.bytes_counter_key_schema.clone();

        if let Some(map) = probe.ebpf.map_mut("bytes_counters") {
            let (map_data, per_cpu) = hash_map_data(map).ok_or_else(|| {
                LoadError::MapNotFound(
                    "Failed to convert bytes_counters map as hash/per-cpu hash".to_string(),
                )
            })?;
            let info = map_data.info().map_err(|e| {
                LoadError::MapNotFound(format!("Failed to query bytes_counters map metadata: {e}"))
            })?;
            let key_size = info.key_size() as usize;
            let value_size = info.value_size() as usize;
            if value_size != 8 {
                return Err(LoadError::MapNotFound(format!(
                    "bytes_counters map has unexpected value size {value_size}"
                )));
            }

            let per_cpu_value_stride = (value_size + 7) & !7;
            let per_cpu_value_buf_len = if per_cpu {
                let nr_cpus = nr_cpus().map_err(|(_, error)| {
                    LoadError::Load(format!(
                        "Failed to determine CPU count for bytes_counters: {error}"
                    ))
                })?;
                nr_cpus * per_cpu_value_stride
            } else {
                value_size
            };

            let fd = map_data.fd().as_fd();
            let mut key = vec![0u8; key_size];
            let mut prev_key: Option<Vec<u8>> = None;

            loop {
                let found =
                    raw_bpf_map_get_next_key(fd, prev_key.as_deref(), &mut key).map_err(|e| {
                        LoadError::MapNotFound(format!("Failed to iterate bytes_counters map: {e}"))
                    })?;
                if !found {
                    break;
                }

                let current_key = key.clone();
                let mut value_buf = vec![0u8; per_cpu_value_buf_len];
                let found =
                    raw_bpf_map_lookup_elem(fd, &current_key, &mut value_buf).map_err(|e| {
                        LoadError::MapNotFound(format!("Failed to lookup bytes_counters key: {e}"))
                    })?;
                if found {
                    let count = if per_cpu {
                        value_buf
                            .chunks(per_cpu_value_stride)
                            .map(decode_i64_le)
                            .sum::<i64>()
                    } else {
                        decode_i64_le(&value_buf)
                    };
                    entries.push(BytesCounterEntry {
                        key: Self::deserialize_bytes_counter_key(&current_key, key_schema.as_ref()),
                        count,
                    });
                }
                prev_key = Some(current_key);
            }
        }

        if entries.len() > MAP_CAPACITY_WARN_THRESHOLD {
            eprintln!(
                "Warning: map 'bytes_counters' is {}% full ({}/{} entries). New entries may be dropped.",
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
