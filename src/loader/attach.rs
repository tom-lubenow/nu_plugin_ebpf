use super::*;

impl EbpfState {
    fn next_probe_id(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Load and attach an eBPF program
    pub fn attach(&self, object: &EbpfObject) -> Result<u32, LoadError> {
        self.attach_with_pin(object, None)
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
        object: &EbpfObject,
        pin_group: Option<&str>,
    ) -> Result<u32, LoadError> {
        match &object.kind {
            crate::compiler::EbpfObjectKind::Program => {
                self.attach_program_object(object, pin_group)
            }
            crate::compiler::EbpfObjectKind::StructOps {
                name,
                value_type_name,
            } => self.attach_struct_ops_object(object, pin_group, name, value_type_name),
        }
    }

    fn attach_program_object(
        &self,
        object: &EbpfObject,
        pin_group: Option<&str>,
    ) -> Result<u32, LoadError> {
        let program = object.primary_program().map_err(LoadError::from)?;

        // Generate ELF
        let elf_bytes = object.to_elf()?;

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
        match program.prog_type.attach_kind() {
            ProgramAttachKind::Kprobe | ProgramAttachKind::Kretprobe => {
                let kprobe: &mut KProbe = prog.try_into().map_err(|e| {
                    LoadError::Load(format!(
                        "Failed to convert to {}: {e}",
                        program.prog_type.canonical_prefix()
                    ))
                })?;
                kprobe.load().map_err(|e| {
                    LoadError::Load(format!(
                        "Failed to load {}: {e}",
                        program.prog_type.canonical_prefix()
                    ))
                })?;
                kprobe.attach(&program.target, 0).map_err(|e| {
                    LoadError::Attach(format!(
                        "Failed to attach {}: {e}",
                        program.prog_type.canonical_prefix()
                    ))
                })?;
            }
            ProgramAttachKind::Fentry => {
                let btf = Btf::from_sys_fs().map_err(|e| {
                    LoadError::Load(format!("Failed to load kernel BTF for fentry: {e}"))
                })?;
                let fentry: &mut FEntry = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to FEntry: {e}")))?;
                fentry
                    .load(&program.target, &btf)
                    .map_err(|e| LoadError::Load(format!("Failed to load fentry: {e}")))?;
                fentry
                    .attach()
                    .map_err(|e| LoadError::Attach(format!("Failed to attach fentry: {e}")))?;
            }
            ProgramAttachKind::Fexit => {
                let btf = Btf::from_sys_fs().map_err(|e| {
                    LoadError::Load(format!("Failed to load kernel BTF for fexit: {e}"))
                })?;
                let fexit: &mut FExit = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to FExit: {e}")))?;
                fexit
                    .load(&program.target, &btf)
                    .map_err(|e| LoadError::Load(format!("Failed to load fexit: {e}")))?;
                fexit
                    .attach()
                    .map_err(|e| LoadError::Attach(format!("Failed to attach fexit: {e}")))?;
            }
            ProgramAttachKind::Tracepoint => {
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
            ProgramAttachKind::RawTracepoint => {
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
            ProgramAttachKind::Uprobe | ProgramAttachKind::Uretprobe => {
                // Uprobe target format: /path/to/binary:function_name or /path/to/binary:0x1234
                let target = UprobeTarget::parse(&program.target)?;
                let uprobe: &mut UProbe = prog.try_into().map_err(|e| {
                    LoadError::Load(format!(
                        "Failed to convert to {}: {e}",
                        program.prog_type.canonical_prefix()
                    ))
                })?;
                uprobe.load().map_err(|e| {
                    LoadError::Load(format!(
                        "Failed to load {}: {e}",
                        program.prog_type.canonical_prefix()
                    ))
                })?;
                uprobe
                    .attach(
                        target.function_name.as_deref(),
                        target.offset,
                        &target.binary_path,
                        target.pid,
                    )
                    .map_err(|e| {
                        LoadError::Attach(format!(
                            "Failed to attach {}: {e}",
                            program.prog_type.canonical_prefix()
                        ))
                    })?;
            }
            ProgramAttachKind::Xdp => {
                let xdp: &mut Xdp = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to Xdp: {e}")))?;
                xdp.load()
                    .map_err(|e| LoadError::Load(format!("Failed to load xdp: {e}")))?;
                xdp.attach(&program.target, XdpFlags::SKB_MODE)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach xdp: {e}")))?;
            }
            ProgramAttachKind::PerfEvent => {
                let target = PerfEventTarget::parse(&program.target)?;
                let perf_event: &mut PerfEvent = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to PerfEvent: {e}")))?;
                perf_event.load().map_err(|e| {
                    LoadError::Load(format!("Failed to load perf_event program: {e}"))
                })?;

                let perf_config = match target.event {
                    PerfEventSoftwareEvent::CpuClock => perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
                    PerfEventSoftwareEvent::TaskClock => {
                        perf_sw_ids::PERF_COUNT_SW_TASK_CLOCK as u64
                    }
                    PerfEventSoftwareEvent::ContextSwitches => {
                        perf_sw_ids::PERF_COUNT_SW_CONTEXT_SWITCHES as u64
                    }
                    PerfEventSoftwareEvent::CpuMigrations => {
                        perf_sw_ids::PERF_COUNT_SW_CPU_MIGRATIONS as u64
                    }
                    PerfEventSoftwareEvent::PageFaults => {
                        perf_sw_ids::PERF_COUNT_SW_PAGE_FAULTS as u64
                    }
                    PerfEventSoftwareEvent::MinorFaults => {
                        perf_sw_ids::PERF_COUNT_SW_PAGE_FAULTS_MIN as u64
                    }
                    PerfEventSoftwareEvent::MajorFaults => {
                        perf_sw_ids::PERF_COUNT_SW_PAGE_FAULTS_MAJ as u64
                    }
                };
                let sample_policy = match target.sample_policy {
                    PerfEventSamplePolicy::Period(period) => SamplePolicy::Period(period),
                    PerfEventSamplePolicy::Frequency(freq) => SamplePolicy::Frequency(freq),
                };

                let cpus = if let Some(cpu) = target.cpu {
                    vec![cpu]
                } else {
                    online_cpus().map_err(|(_, e)| {
                        LoadError::Attach(format!("Failed to enumerate online CPUs: {e}"))
                    })?
                };

                for cpu in cpus {
                    perf_event
                        .attach(
                            PerfTypeId::Software,
                            perf_config,
                            PerfEventScope::AllProcessesOneCpu { cpu },
                            sample_policy.clone(),
                            true,
                        )
                        .map_err(|e| {
                            LoadError::Attach(format!(
                                "Failed to attach perf_event on cpu {cpu}: {e}"
                            ))
                        })?;
                }
            }
            ProgramAttachKind::Tc => {
                let target = TcTarget::parse(&program.target)?;
                let classifier: &mut SchedClassifier = prog.try_into().map_err(|e| {
                    LoadError::Load(format!("Failed to convert to SchedClassifier: {e}"))
                })?;
                classifier
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load tc classifier: {e}")))?;
                match tc::qdisc_add_clsact(&target.interface) {
                    Ok(()) => {}
                    Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                    Err(e) => {
                        return Err(LoadError::Attach(format!(
                            "Failed to add clsact qdisc on {}: {e}",
                            target.interface
                        )));
                    }
                }
                classifier
                    .attach(&target.interface, target.attach_type)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach tc: {e}")))?;
            }
            ProgramAttachKind::CgroupSkb => {
                let target = CgroupSkbTarget::parse(&program.target)?;
                let cgroup = std::fs::File::open(&target.cgroup_path).map_err(|e| {
                    if e.kind() == ErrorKind::PermissionDenied {
                        LoadError::PermissionDenied
                    } else {
                        LoadError::Attach(format!(
                            "Failed to open cgroup path {}: {e}",
                            target.cgroup_path
                        ))
                    }
                })?;
                let cgroup_skb: &mut CgroupSkb = prog
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("Failed to convert to CgroupSkb: {e}")))?;
                cgroup_skb
                    .load()
                    .map_err(|e| LoadError::Load(format!("Failed to load cgroup_skb: {e}")))?;
                cgroup_skb
                    .attach(cgroup, target.attach_type, CgroupAttachMode::Single)
                    .map_err(|e| LoadError::Attach(format!("Failed to attach cgroup_skb: {e}")))?;
            }
            ProgramAttachKind::CgroupSockAddr => {
                let target = CgroupSockAddrTarget::parse(&program.target)?;
                let cgroup = std::fs::File::open(&target.cgroup_path).map_err(|e| {
                    if e.kind() == ErrorKind::PermissionDenied {
                        LoadError::PermissionDenied
                    } else {
                        LoadError::Attach(format!(
                            "Failed to open cgroup path {}: {e}",
                            target.cgroup_path
                        ))
                    }
                })?;
                let cgroup_sock_addr: &mut CgroupSockAddr = prog.try_into().map_err(|e| {
                    LoadError::Load(format!("Failed to convert to CgroupSockAddr: {e}"))
                })?;
                cgroup_sock_addr.load().map_err(|e| {
                    LoadError::Load(format!("Failed to load cgroup_sock_addr: {e}"))
                })?;
                cgroup_sock_addr
                    .attach(cgroup, CgroupAttachMode::Single)
                    .map_err(|e| {
                        LoadError::Attach(format!("Failed to attach cgroup_sock_addr: {e}"))
                    })?;
            }
            ProgramAttachKind::StructOps => {
                return Err(LoadError::Load(
                    "struct_ops callbacks are not directly attachable; emit them through a struct_ops object instead"
                        .to_string(),
                ));
            }
        }

        // Check for maps
        let has_ringbuf = ebpf.map("events").is_some();
        let has_counter_map = ebpf.map("counters").is_some();
        let has_string_counter_map = ebpf.map("str_counters").is_some();
        let has_bytes_counter_map = ebpf.map("bytes_counters").is_some();
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
        let probe_spec = format!(
            "{}:{}",
            program.prog_type.canonical_prefix(),
            program.target
        );

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
            aya_ebpf: Some(ebpf),
            struct_ops: None,
            has_ringbuf,
            has_counter_map,
            has_string_counter_map,
            has_bytes_counter_map,
            has_histogram_map,
            has_kstack_map,
            has_ustack_map,
            ringbuf,
            event_schema: program.event_schema.clone(),
            bytes_counter_key_schema: program.bytes_counter_key_schema.clone(),
            generic_map_value_types: program.generic_map_value_types.clone(),
            pin_group: pin_group_owned,
        };

        self.probes
            .lock()
            .map_err(|_| LoadError::LockPoisoned)?
            .insert(id, active_probe);

        Ok(id)
    }

    fn attach_struct_ops_object(
        &self,
        object: &EbpfObject,
        pin_group: Option<&str>,
        name: &str,
        value_type_name: &str,
    ) -> Result<u32, LoadError> {
        if pin_group.is_some() {
            return Err(LoadError::Load(
                "struct_ops objects do not yet support pinned map sharing".to_string(),
            ));
        }

        let elf_bytes = object.to_elf()?;
        let handle = LibbpfStructOpsHandle::load_and_attach(elf_bytes, name)?;
        let id = self.next_probe_id();

        let active_probe = ActiveProbe {
            id,
            probe_spec: format!("struct_ops:{name}:{value_type_name}"),
            attached_at: Instant::now(),
            aya_ebpf: None,
            struct_ops: Some(handle),
            has_ringbuf: false,
            has_counter_map: false,
            has_string_counter_map: false,
            has_bytes_counter_map: false,
            has_histogram_map: false,
            has_kstack_map: false,
            has_ustack_map: false,
            ringbuf: None,
            event_schema: None,
            bytes_counter_key_schema: None,
            generic_map_value_types: HashMap::new(),
            pin_group: None,
        };

        self.probes
            .lock()
            .map_err(|_| LoadError::LockPoisoned)?
            .insert(id, active_probe);

        Ok(id)
    }
}
