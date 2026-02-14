use super::*;

impl EbpfState {
    fn next_probe_id(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Load and attach an eBPF program
    pub fn attach(&self, program: &EbpfProgram) -> Result<u32, LoadError> {
        self.attach_with_pin(program, None)
    }

    /// Load and attach an eBPF program with optional map pinning
    ///
    /// If `pin_group` is Some, maps will be pinned to /sys/fs/bpf/nushell/<group>/.
    /// This enables map sharing between separate eBPF programs - for example, a kprobe
    /// and kretprobe can share a timestamp map for latency measurement via start-timer/stop-timer.
    ///
    /// When a pinned map already exists, the new program will reuse it instead of creating a new one.
    /// Maps are automatically unpinned when no programs are using them.
    pub fn attach_with_pin(
        &self,
        program: &EbpfProgram,
        pin_group: Option<&str>,
    ) -> Result<u32, LoadError> {
        // Generate ELF
        let elf_bytes = program.to_elf()?;

        // Load with Aya using EbpfLoader for optional map pinning
        let mut ebpf = if let Some(group) = pin_group {
            let pin_path = format!("/sys/fs/bpf/nushell/{}", group);
            // Create the directory if it doesn't exist
            std::fs::create_dir_all(&pin_path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    LoadError::PermissionDenied
                } else {
                    LoadError::Load(format!(
                        "Failed to create pin directory {}: {}",
                        pin_path, e
                    ))
                }
            })?;
            // Use EbpfLoader with map pinning to enable map sharing between programs
            EbpfLoader::new().map_pin_path(&pin_path).load(&elf_bytes)
        } else {
            // No pinning - use simple Ebpf::load
            Ebpf::load(&elf_bytes)
        }
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("EPERM") || msg.contains("permission") {
                LoadError::PermissionDenied
            } else {
                LoadError::Load(msg)
            }
        })?;

        // Get the program by name
        let prog = ebpf
            .program_mut(&program.name)
            .ok_or_else(|| LoadError::ProgramNotFound(program.name.clone()))?;

        // Attach based on program type
        match program.prog_type {
            EbpfProgramType::Kprobe => {
                let kprobe: &mut KProbe = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to KProbe: {e}")))?;
                kprobe
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load kprobe: {e}")))?;
                kprobe
                    .attach(&program.target, 0)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach kprobe: {e}")))?;
            }
            EbpfProgramType::Kretprobe => {
                // Kretprobe uses the same KProbe type - Aya detects it from the section name
                let kretprobe: &mut KProbe = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to KRetProbe: {e}")))?;
                kretprobe
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load kretprobe: {e}")))?;
                kretprobe
                    .attach(&program.target, 0)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach kretprobe: {e}")))?;
            }
            EbpfProgramType::Tracepoint => {
                // Tracepoint target format: "category/name" (e.g., "syscalls/sys_enter_openat")
                let parts: Vec<&str> = program.target.splitn(2, '/').collect();
                if parts.len() != 2 {
                    return Err(LoadError::Load(format!(
                        "Invalid tracepoint target: {}. Expected format: category/name",
                        program.target
                    )));
                }
                let (category, name) = (parts[0], parts[1]);

                let tracepoint: &mut TracePoint = prog.try_into().map_err(|e| {
                    LoadError::Load(format!("Failed to convert to TracePoint: {e}"))
                })?;
                tracepoint
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load tracepoint: {e}")))?;
                tracepoint
                    .attach(category, name)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach tracepoint: {e}")))?;
            }
            EbpfProgramType::RawTracepoint => {
                // Raw tracepoint target is just the name (e.g., "sys_enter")
                let raw_tp: &mut RawTracePoint = prog.try_into().map_err(|e| {
                    LoadError::Load(format!("Failed to convert to RawTracePoint: {e}"))
                })?;
                raw_tp
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load raw_tracepoint: {e}")))?;
                raw_tp.attach(&program.target).map_err(|e| {
                    LoadError::Attach(format!("Failed to attach raw_tracepoint: {e}"))
                })?;
            }
            EbpfProgramType::Uprobe => {
                // Uprobe target format: /path/to/binary:function_name or /path/to/binary:0x1234
                let target = UprobeTarget::parse(&program.target)?;
                let uprobe: &mut UProbe = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to UProbe: {e}")))?;
                uprobe
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load uprobe: {e}")))?;
                uprobe
                    .attach(
                        target.function_name.as_deref(),
                        target.offset,
                        &target.binary_path,
                        target.pid,
                    )
                    .map_err(|e| LoadError::Attach(format!("Failed to attach uprobe: {e}")))?;
            }
            EbpfProgramType::Uretprobe => {
                // Uretprobe uses the same UProbe type - Aya detects it from the section name
                let target = UprobeTarget::parse(&program.target)?;
                let uretprobe: &mut UProbe = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to URetProbe: {e}")))?;
                uretprobe
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load uretprobe: {e}")))?;
                uretprobe
                    .attach(
                        target.function_name.as_deref(),
                        target.offset,
                        &target.binary_path,
                        target.pid,
                    )
                    .map_err(|e| LoadError::Attach(format!("Failed to attach uretprobe: {e}")))?;
            }
        }

        // Check for maps
        let has_ringbuf = ebpf.map("events").is_some();
        let has_counter_map = ebpf.map("counters").is_some();
        let has_string_counter_map = ebpf.map("str_counters").is_some();
        let has_histogram_map = ebpf.map("histogram").is_some();
        let has_kstack_map = ebpf.map("kstacks").is_some();
        let has_ustack_map = ebpf.map("ustacks").is_some();

        // Set up ring buffer if the program uses bpf-emit
        let ringbuf = if has_ringbuf {
            let ring_map = ebpf
                .take_map("events")
                .ok_or_else(|| LoadError::MapNotFound("events".to_string()))?;

            let ringbuf = RingBuf::try_from(ring_map).map_err(|e| {
                LoadError::PerfBuffer(format!("Failed to convert ring buffer map: {e}"))
            })?;

            Some(ringbuf)
        } else {
            None
        };

        // Store the active probe
        let id = self.next_probe_id();
        let probe_spec = format!("{}:{}", program.prog_type.section_prefix(), program.target);

        // Track pin group reference count for cleanup
        let pin_group_owned = pin_group.map(|s| s.to_string());
        if let Some(ref group) = pin_group_owned {
            let mut refs = self
                .pin_group_refs
                .lock()
                .map_err(|_| LoadError::LockPoisoned)?;
            *refs.entry(group.clone()).or_insert(0) += 1;
        }

        let active_probe = ActiveProbe {
            id,
            probe_spec,
            attached_at: Instant::now(),
            ebpf,
            has_ringbuf,
            has_counter_map,
            has_string_counter_map,
            has_histogram_map,
            has_kstack_map,
            has_ustack_map,
            ringbuf,
            event_schema: program.event_schema.clone(),
            pin_group: pin_group_owned,
        };

        self.probes
            .lock()
            .map_err(|_| LoadError::LockPoisoned)?
            .insert(id, active_probe);

        Ok(id)
    }
}
