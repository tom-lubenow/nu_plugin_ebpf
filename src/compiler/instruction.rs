//! eBPF instruction encoding
//!
//! eBPF instructions are 64-bit fixed-length, encoded as:
//! ```text
//! opcode:8 src_reg:4 dst_reg:4 offset:16 imm:32
//! ```
//!
//! Some instructions (like 64-bit immediate loads) use two 64-bit slots.

/// eBPF register identifiers (r0-r10)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EbpfReg {
    /// Return value from functions, exit value for eBPF program
    R0 = 0,
    /// First argument to BPF helpers, also context pointer
    R1 = 1,
    /// Second argument to BPF helpers
    R2 = 2,
    /// Third argument to BPF helpers
    R3 = 3,
    /// Fourth argument to BPF helpers
    R4 = 4,
    /// Fifth argument to BPF helpers
    R5 = 5,
    /// Callee-saved register
    R6 = 6,
    /// Callee-saved register
    R7 = 7,
    /// Callee-saved register
    R8 = 8,
    /// Callee-saved register
    R9 = 9,
    /// Frame pointer (read-only)
    R10 = 10,
}

impl EbpfReg {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// BPF helper function numbers
///
/// These are the kernel helper functions that eBPF programs can call.
/// See: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum BpfHelper {
    /// void *bpf_map_lookup_elem(map, key)
    MapLookupElem = 1,
    /// int bpf_map_update_elem(map, key, value, flags)
    MapUpdateElem = 2,
    /// int bpf_map_delete_elem(map, key)
    MapDeleteElem = 3,
    /// int bpf_probe_read(dst, size, src)
    ProbeRead = 4,
    /// u64 bpf_ktime_get_ns(void)
    KtimeGetNs = 5,
    /// int bpf_trace_printk(fmt, fmt_size, ...)
    TracePrintk = 6,
    /// u32 bpf_get_smp_processor_id(void)
    GetSmpProcessorId = 8,
    /// long bpf_tail_call(ctx, prog_array_map, index)
    TailCall = 12,
    /// u64 bpf_get_current_pid_tgid(void)
    GetCurrentPidTgid = 14,
    /// u64 bpf_get_current_uid_gid(void)
    GetCurrentUidGid = 15,
    /// int bpf_get_current_comm(buf, size)
    GetCurrentComm = 16,
    /// int bpf_perf_event_output(ctx, map, flags, data, size)
    PerfEventOutput = 25,
    /// long bpf_get_stackid(ctx, map, flags)
    GetStackId = 27,
    /// long bpf_ringbuf_output(map, data, size, flags)
    RingbufOutput = 130,
    /// void *bpf_ringbuf_reserve(map, size, flags)
    RingbufReserve = 131,
    /// void bpf_ringbuf_submit(data, flags)
    RingbufSubmit = 132,
    /// void bpf_ringbuf_discard(data, flags)
    RingbufDiscard = 133,
    /// void *bpf_kptr_xchg(dst, ptr)
    KptrXchg = 194,
    /// long bpf_probe_read_user_str(dst, size, unsafe_ptr)
    ProbeReadUserStr = 114,
    /// long bpf_probe_read_kernel_str(dst, size, unsafe_ptr)
    ProbeReadKernelStr = 115,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperArgKind {
    Scalar,
    Pointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperRetKind {
    Scalar,
    PointerMaybeNull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncArgKind {
    Scalar,
    Pointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncRetKind {
    Scalar,
    PointerMaybeNull,
    Void,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncRefKind {
    Task,
    Cgroup,
    Cpumask,
    Object,
    File,
}

impl KfuncRefKind {
    pub const fn label(self) -> &'static str {
        match self {
            KfuncRefKind::Task => "task",
            KfuncRefKind::Cgroup => "cgroup",
            KfuncRefKind::Cpumask => "cpumask",
            KfuncRefKind::Object => "object",
            KfuncRefKind::File => "file",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperAllowedPtrSpaces {
    pub allow_stack: bool,
    pub allow_map: bool,
    pub allow_kernel: bool,
    pub allow_user: bool,
}

impl HelperAllowedPtrSpaces {
    pub const fn new(
        allow_stack: bool,
        allow_map: bool,
        allow_kernel: bool,
        allow_user: bool,
    ) -> Self {
        Self {
            allow_stack,
            allow_map,
            allow_kernel,
            allow_user,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperPtrArgRule {
    pub arg_idx: usize,
    pub op: &'static str,
    pub allowed: HelperAllowedPtrSpaces,
    pub fixed_size: Option<usize>,
    pub size_from_arg: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
pub struct HelperSemantics {
    pub ptr_arg_rules: &'static [HelperPtrArgRule],
    pub positive_size_args: &'static [usize],
    pub ringbuf_record_arg0: bool,
}

impl HelperSemantics {
    pub const EMPTY: Self = Self {
        ptr_arg_rules: &[],
        positive_size_args: &[],
        ringbuf_record_arg0: false,
    };
}

#[derive(Debug, Clone, Copy)]
pub struct HelperSignature {
    pub min_args: usize,
    pub max_args: usize,
    pub arg_kinds: [HelperArgKind; 5],
    pub ret_kind: HelperRetKind,
}

impl HelperSignature {
    pub const fn for_id(helper_id: u32) -> Option<Self> {
        match BpfHelper::from_u32(helper_id) {
            Some(helper) => Some(helper.signature()),
            None => None,
        }
    }

    pub const fn arg_kind(&self, idx: usize) -> HelperArgKind {
        self.arg_kinds[idx]
    }
}

#[derive(Debug, Clone, Copy)]
pub struct KfuncSignature {
    pub min_args: usize,
    pub max_args: usize,
    pub arg_kinds: [KfuncArgKind; 5],
    pub ret_kind: KfuncRetKind,
}

impl KfuncSignature {
    pub fn for_name(name: &str) -> Option<Self> {
        const S: KfuncArgKind = KfuncArgKind::Scalar;
        const P: KfuncArgKind = KfuncArgKind::Pointer;

        match name {
            "bpf_task_acquire" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_task_release" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "bpf_task_from_pid" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_task_from_vpid" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_task_get_cgroup1" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_task_under_cgroup" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_cgroup_acquire" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_cgroup_ancestor" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_cgroup_from_id" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_cgroup_release" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "bpf_get_task_exe_file" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_put_file" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "bpf_path_d_path" => Some(Self {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_throw" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "bpf_iter_task_vma_new" => Some(Self {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_iter_task_vma_next" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_iter_task_vma_destroy" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "bpf_obj_drop_impl" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "bpf_obj_new_impl" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_refcount_acquire_impl" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_percpu_obj_new_impl" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_percpu_obj_drop_impl" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "bpf_list_push_front_impl" => Some(Self {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_list_push_back_impl" => Some(Self {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_list_pop_front" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_list_pop_back" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_rbtree_remove" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_rbtree_add_impl" => Some(Self {
                min_args: 5,
                max_args: 5,
                arg_kinds: [P, P, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_rbtree_first" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_cpumask_create" => Some(Self {
                min_args: 0,
                max_args: 0,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_cpumask_acquire" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::PointerMaybeNull,
            }),
            "bpf_cpumask_release" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "bpf_cpumask_and" => Some(Self {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, P, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_cpumask_any_and_distribute" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_cpumask_any_distribute" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_cpumask_clear" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "bpf_cpumask_clear_cpu" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [S, P, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "bpf_cpumask_copy" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "bpf_cpumask_empty" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_cpumask_equal" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_cpumask_first" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_cpumask_first_and" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_cpumask_first_zero" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_cpumask_full" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_cpumask_intersects" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_cpumask_or" => Some(Self {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, P, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "bpf_cpumask_set_cpu" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [S, P, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "bpf_cpumask_setall" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "bpf_cpumask_subset" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_cpumask_test_and_clear_cpu" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [S, P, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_cpumask_test_and_set_cpu" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [S, P, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_cpumask_test_cpu" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [S, P, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_cpumask_weight" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "bpf_cpumask_xor" => Some(Self {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, P, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "scx_bpf_cpu_node" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "scx_bpf_cpuperf_cap" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "scx_bpf_cpuperf_cur" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "scx_bpf_cpuperf_set" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "scx_bpf_create_dsq" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "scx_bpf_destroy_dsq" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "scx_bpf_dispatch_cancel" => Some(Self {
                min_args: 0,
                max_args: 0,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "scx_bpf_dispatch_nr_slots" => Some(Self {
                min_args: 0,
                max_args: 0,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "scx_bpf_dsq_insert" => Some(Self {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "scx_bpf_dsq_insert_vtime" => Some(Self {
                min_args: 5,
                max_args: 5,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "scx_bpf_dsq_move_to_local" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "scx_bpf_dsq_nr_queued" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "scx_bpf_kick_cpu" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::Void,
            }),
            "scx_bpf_now" => Some(Self {
                min_args: 0,
                max_args: 0,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "scx_bpf_nr_cpu_ids" => Some(Self {
                min_args: 0,
                max_args: 0,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "scx_bpf_nr_node_ids" => Some(Self {
                min_args: 0,
                max_args: 0,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "scx_bpf_pick_any_cpu" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "scx_bpf_pick_any_cpu_node" => Some(Self {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "scx_bpf_pick_idle_cpu" => Some(Self {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "scx_bpf_pick_idle_cpu_node" => Some(Self {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "scx_bpf_reenqueue_local" => Some(Self {
                min_args: 0,
                max_args: 0,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "scx_bpf_task_cpu" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "scx_bpf_task_running" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            "scx_bpf_test_and_clear_cpu_idle" => Some(Self {
                min_args: 1,
                max_args: 1,
                arg_kinds: [S, S, S, S, S],
                ret_kind: KfuncRetKind::Scalar,
            }),
            _ => None,
        }
    }

    pub fn arg_kind(&self, idx: usize) -> KfuncArgKind {
        self.arg_kinds[idx]
    }
}

pub fn kfunc_acquire_ref_kind(kfunc: &str) -> Option<KfuncRefKind> {
    match kfunc {
        "bpf_task_acquire" | "bpf_task_from_pid" | "bpf_task_from_vpid" => Some(KfuncRefKind::Task),
        "bpf_task_get_cgroup1" | "bpf_cgroup_acquire" | "bpf_cgroup_from_id" => {
            Some(KfuncRefKind::Cgroup)
        }
        "bpf_get_task_exe_file" => Some(KfuncRefKind::File),
        "bpf_obj_new_impl" | "bpf_refcount_acquire_impl" | "bpf_percpu_obj_new_impl" => {
            Some(KfuncRefKind::Object)
        }
        "bpf_cpumask_create" | "bpf_cpumask_acquire" => Some(KfuncRefKind::Cpumask),
        _ => None,
    }
}

pub fn kfunc_release_ref_kind(kfunc: &str) -> Option<KfuncRefKind> {
    match kfunc {
        "bpf_task_release" => Some(KfuncRefKind::Task),
        "bpf_cgroup_release" => Some(KfuncRefKind::Cgroup),
        "bpf_put_file" => Some(KfuncRefKind::File),
        "bpf_obj_drop_impl" | "bpf_percpu_obj_drop_impl" => Some(KfuncRefKind::Object),
        "bpf_cpumask_release" => Some(KfuncRefKind::Cpumask),
        _ => None,
    }
}

pub fn kfunc_pointer_arg_ref_kind(kfunc: &str, arg_idx: usize) -> Option<KfuncRefKind> {
    if matches!(
        (kfunc, arg_idx),
        ("bpf_task_acquire", 0)
            | ("bpf_task_release", 0)
            | ("bpf_task_get_cgroup1", 0)
            | ("bpf_task_under_cgroup", 0)
            | ("bpf_get_task_exe_file", 0)
            | ("bpf_iter_task_vma_new", 1)
            | ("scx_bpf_dsq_insert", 0)
            | ("scx_bpf_dsq_insert_vtime", 0)
            | ("scx_bpf_task_cpu", 0)
            | ("scx_bpf_task_running", 0)
    ) {
        return Some(KfuncRefKind::Task);
    }
    if matches!(
        (kfunc, arg_idx),
        ("bpf_task_under_cgroup", 1)
            | ("bpf_cgroup_acquire", 0)
            | ("bpf_cgroup_ancestor", 0)
            | ("bpf_cgroup_release", 0)
    ) {
        return Some(KfuncRefKind::Cgroup);
    }
    if matches!(
        (kfunc, arg_idx),
        ("bpf_obj_drop_impl", 0)
            | ("bpf_refcount_acquire_impl", 0)
            | ("bpf_percpu_obj_drop_impl", 0)
    ) {
        return Some(KfuncRefKind::Object);
    }
    if matches!((kfunc, arg_idx), ("bpf_put_file", 0)) {
        return Some(KfuncRefKind::File);
    }
    if matches!(
        (kfunc, arg_idx),
        ("bpf_cpumask_acquire", 0)
            | ("bpf_cpumask_release", 0)
            | ("bpf_cpumask_and", 0)
            | ("bpf_cpumask_and", 1)
            | ("bpf_cpumask_and", 2)
            | ("bpf_cpumask_any_and_distribute", 0)
            | ("bpf_cpumask_any_and_distribute", 1)
            | ("bpf_cpumask_any_distribute", 0)
            | ("bpf_cpumask_clear", 0)
            | ("bpf_cpumask_clear_cpu", 1)
            | ("bpf_cpumask_copy", 0)
            | ("bpf_cpumask_copy", 1)
            | ("bpf_cpumask_empty", 0)
            | ("bpf_cpumask_equal", 0)
            | ("bpf_cpumask_equal", 1)
            | ("bpf_cpumask_first", 0)
            | ("bpf_cpumask_first_and", 0)
            | ("bpf_cpumask_first_and", 1)
            | ("bpf_cpumask_first_zero", 0)
            | ("bpf_cpumask_full", 0)
            | ("bpf_cpumask_intersects", 0)
            | ("bpf_cpumask_intersects", 1)
            | ("bpf_cpumask_or", 0)
            | ("bpf_cpumask_or", 1)
            | ("bpf_cpumask_or", 2)
            | ("bpf_cpumask_set_cpu", 1)
            | ("bpf_cpumask_setall", 0)
            | ("bpf_cpumask_subset", 0)
            | ("bpf_cpumask_subset", 1)
            | ("bpf_cpumask_test_and_clear_cpu", 1)
            | ("bpf_cpumask_test_and_set_cpu", 1)
            | ("bpf_cpumask_test_cpu", 1)
            | ("bpf_cpumask_weight", 0)
            | ("bpf_cpumask_xor", 0)
            | ("bpf_cpumask_xor", 1)
            | ("bpf_cpumask_xor", 2)
            | ("scx_bpf_pick_any_cpu", 0)
            | ("scx_bpf_pick_any_cpu_node", 0)
            | ("scx_bpf_pick_idle_cpu", 0)
            | ("scx_bpf_pick_idle_cpu_node", 0)
    ) {
        return Some(KfuncRefKind::Cpumask);
    }
    None
}

pub fn kfunc_pointer_arg_requires_kernel(kfunc: &str, arg_idx: usize) -> bool {
    if kfunc_pointer_arg_ref_kind(kfunc, arg_idx).is_some() {
        return true;
    }
    matches!(
        (kfunc, arg_idx),
        ("bpf_list_push_front_impl", 0)
            | ("bpf_list_push_front_impl", 1)
            | ("bpf_list_push_back_impl", 0)
            | ("bpf_list_push_back_impl", 1)
            | ("bpf_list_pop_front", 0)
            | ("bpf_list_pop_back", 0)
            | ("bpf_path_d_path", 0)
            | ("bpf_rbtree_remove", 0)
            | ("bpf_rbtree_remove", 1)
            | ("bpf_rbtree_add_impl", 0)
            | ("bpf_rbtree_add_impl", 1)
            | ("bpf_rbtree_first", 0)
    )
}

impl BpfHelper {
    pub const fn from_u32(helper_id: u32) -> Option<Self> {
        match helper_id {
            1 => Some(Self::MapLookupElem),
            2 => Some(Self::MapUpdateElem),
            3 => Some(Self::MapDeleteElem),
            4 => Some(Self::ProbeRead),
            5 => Some(Self::KtimeGetNs),
            6 => Some(Self::TracePrintk),
            8 => Some(Self::GetSmpProcessorId),
            12 => Some(Self::TailCall),
            14 => Some(Self::GetCurrentPidTgid),
            15 => Some(Self::GetCurrentUidGid),
            16 => Some(Self::GetCurrentComm),
            25 => Some(Self::PerfEventOutput),
            27 => Some(Self::GetStackId),
            114 => Some(Self::ProbeReadUserStr),
            115 => Some(Self::ProbeReadKernelStr),
            130 => Some(Self::RingbufOutput),
            131 => Some(Self::RingbufReserve),
            132 => Some(Self::RingbufSubmit),
            133 => Some(Self::RingbufDiscard),
            194 => Some(Self::KptrXchg),
            _ => None,
        }
    }

    pub const fn signature(self) -> HelperSignature {
        const S: HelperArgKind = HelperArgKind::Scalar;
        const P: HelperArgKind = HelperArgKind::Pointer;
        match self {
            BpfHelper::MapLookupElem => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::MapUpdateElem => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, P, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::MapDeleteElem => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::ProbeRead => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, S, P, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::KtimeGetNs
            | BpfHelper::GetSmpProcessorId
            | BpfHelper::GetCurrentPidTgid
            | BpfHelper::GetCurrentUidGid => HelperSignature {
                min_args: 0,
                max_args: 0,
                arg_kinds: [S, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::TracePrintk => HelperSignature {
                min_args: 2,
                max_args: 5,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::TailCall => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::GetCurrentComm => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::PerfEventOutput => HelperSignature {
                min_args: 5,
                max_args: 5,
                arg_kinds: [P, P, S, P, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::GetStackId => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::RingbufOutput => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::RingbufReserve => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::RingbufSubmit | BpfHelper::RingbufDiscard => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::KptrXchg => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::ProbeReadUserStr | BpfHelper::ProbeReadKernelStr => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, S, P, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
        }
    }

    pub const fn semantics(self) -> HelperSemantics {
        const STACK_MAP: HelperAllowedPtrSpaces =
            HelperAllowedPtrSpaces::new(true, true, false, false);
        const MAP_ONLY: HelperAllowedPtrSpaces =
            HelperAllowedPtrSpaces::new(false, true, false, false);
        const STACK_ONLY: HelperAllowedPtrSpaces =
            HelperAllowedPtrSpaces::new(true, false, false, false);
        const STACK_MAP_KERNEL: HelperAllowedPtrSpaces =
            HelperAllowedPtrSpaces::new(true, true, true, false);
        const KERNEL: HelperAllowedPtrSpaces =
            HelperAllowedPtrSpaces::new(false, false, true, false);
        const USER: HelperAllowedPtrSpaces = HelperAllowedPtrSpaces::new(false, false, false, true);

        const MAP_LOOKUP_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper map_lookup map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper map_lookup key",
                allowed: STACK_MAP,
                fixed_size: Some(1),
                size_from_arg: None,
            },
        ];

        const MAP_UPDATE_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper map_update map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper map_update key",
                allowed: STACK_MAP,
                fixed_size: Some(1),
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 2,
                op: "helper map_update value",
                allowed: STACK_MAP,
                fixed_size: Some(1),
                size_from_arg: None,
            },
        ];

        const MAP_DELETE_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper map_delete map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper map_delete key",
                allowed: STACK_MAP,
                fixed_size: Some(1),
                size_from_arg: None,
            },
        ];

        const GET_CURRENT_COMM_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper get_current_comm dst",
            allowed: STACK_MAP,
            fixed_size: None,
            size_from_arg: Some(1),
        }];

        const TRACE_PRINTK_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper trace_printk fmt",
            allowed: STACK_MAP,
            fixed_size: None,
            size_from_arg: Some(1),
        }];

        const PROBE_READ_KERNEL_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper probe_read dst",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(1),
            },
            HelperPtrArgRule {
                arg_idx: 2,
                op: "helper probe_read src",
                allowed: STACK_MAP_KERNEL,
                fixed_size: None,
                size_from_arg: Some(1),
            },
        ];

        const PROBE_READ_USER_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper probe_read dst",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(1),
            },
            HelperPtrArgRule {
                arg_idx: 2,
                op: "helper probe_read src",
                allowed: USER,
                fixed_size: None,
                size_from_arg: Some(1),
            },
        ];

        const RINGBUF_RESERVE_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper ringbuf_reserve map",
            allowed: STACK_ONLY,
            fixed_size: None,
            size_from_arg: None,
        }];

        const RINGBUF_OUTPUT_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper ringbuf_output map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper ringbuf_output data",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(2),
            },
        ];

        const TAIL_CALL_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper tail_call ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper tail_call map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
        ];

        const PERF_EVENT_OUTPUT_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper perf_event_output ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper perf_event_output map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 3,
                op: "helper perf_event_output data",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(4),
            },
        ];

        const GET_STACKID_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper get_stackid ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper get_stackid map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
        ];

        const KPTR_XCHG_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper kptr_xchg dst",
                allowed: MAP_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper kptr_xchg ptr",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
        ];

        match self {
            BpfHelper::MapLookupElem => HelperSemantics {
                ptr_arg_rules: MAP_LOOKUP_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::MapUpdateElem => HelperSemantics {
                ptr_arg_rules: MAP_UPDATE_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::MapDeleteElem => HelperSemantics {
                ptr_arg_rules: MAP_DELETE_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::GetCurrentComm => HelperSemantics {
                ptr_arg_rules: GET_CURRENT_COMM_RULES,
                positive_size_args: &[1],
                ringbuf_record_arg0: false,
            },
            BpfHelper::TracePrintk => HelperSemantics {
                ptr_arg_rules: TRACE_PRINTK_RULES,
                positive_size_args: &[1],
                ringbuf_record_arg0: false,
            },
            BpfHelper::ProbeRead | BpfHelper::ProbeReadKernelStr => HelperSemantics {
                ptr_arg_rules: PROBE_READ_KERNEL_RULES,
                positive_size_args: &[1],
                ringbuf_record_arg0: false,
            },
            BpfHelper::ProbeReadUserStr => HelperSemantics {
                ptr_arg_rules: PROBE_READ_USER_RULES,
                positive_size_args: &[1],
                ringbuf_record_arg0: false,
            },
            BpfHelper::RingbufReserve => HelperSemantics {
                ptr_arg_rules: RINGBUF_RESERVE_RULES,
                positive_size_args: &[1],
                ringbuf_record_arg0: false,
            },
            BpfHelper::RingbufOutput => HelperSemantics {
                ptr_arg_rules: RINGBUF_OUTPUT_RULES,
                positive_size_args: &[2],
                ringbuf_record_arg0: false,
            },
            BpfHelper::TailCall => HelperSemantics {
                ptr_arg_rules: TAIL_CALL_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::RingbufSubmit | BpfHelper::RingbufDiscard => HelperSemantics {
                ptr_arg_rules: &[],
                positive_size_args: &[],
                ringbuf_record_arg0: true,
            },
            BpfHelper::PerfEventOutput => HelperSemantics {
                ptr_arg_rules: PERF_EVENT_OUTPUT_RULES,
                positive_size_args: &[4],
                ringbuf_record_arg0: false,
            },
            BpfHelper::GetStackId => HelperSemantics {
                ptr_arg_rules: GET_STACKID_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::KptrXchg => HelperSemantics {
                ptr_arg_rules: KPTR_XCHG_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            _ => HelperSemantics::EMPTY,
        }
    }
}

/// eBPF instruction opcodes
pub mod opcode {
    // Instruction classes (3 bits)
    pub const BPF_LD: u8 = 0x00;
    pub const BPF_LDX: u8 = 0x01;
    pub const BPF_ST: u8 = 0x02;
    pub const BPF_STX: u8 = 0x03;
    pub const BPF_ALU: u8 = 0x04;
    pub const BPF_JMP: u8 = 0x05;
    pub const BPF_JMP32: u8 = 0x06;
    pub const BPF_ALU64: u8 = 0x07;

    // Size modifiers (2 bits)
    pub const BPF_W: u8 = 0x00; // 32-bit
    pub const BPF_H: u8 = 0x08; // 16-bit
    pub const BPF_B: u8 = 0x10; // 8-bit
    pub const BPF_DW: u8 = 0x18; // 64-bit

    // Source modifiers
    pub const BPF_K: u8 = 0x00; // Immediate
    pub const BPF_X: u8 = 0x08; // Register

    // ALU operations (4 bits, shifted left by 4)
    pub const BPF_ADD: u8 = 0x00;
    pub const BPF_SUB: u8 = 0x10;
    pub const BPF_MUL: u8 = 0x20;
    pub const BPF_DIV: u8 = 0x30;
    pub const BPF_OR: u8 = 0x40;
    pub const BPF_AND: u8 = 0x50;
    pub const BPF_LSH: u8 = 0x60;
    pub const BPF_RSH: u8 = 0x70;
    pub const BPF_NEG: u8 = 0x80;
    pub const BPF_MOD: u8 = 0x90;
    pub const BPF_XOR: u8 = 0xa0;
    pub const BPF_MOV: u8 = 0xb0;
    pub const BPF_ARSH: u8 = 0xc0; // Arithmetic right shift

    // Jump operations
    pub const BPF_JA: u8 = 0x00; // Jump always
    pub const BPF_JEQ: u8 = 0x10; // Jump if equal
    pub const BPF_JGT: u8 = 0x20; // Jump if greater than
    pub const BPF_JGE: u8 = 0x30; // Jump if greater or equal
    pub const BPF_JSET: u8 = 0x40; // Jump if set (bitwise AND)
    pub const BPF_JNE: u8 = 0x50; // Jump if not equal
    pub const BPF_JSGT: u8 = 0x60; // Jump if signed greater than
    pub const BPF_JSGE: u8 = 0x70; // Jump if signed greater or equal
    pub const BPF_CALL: u8 = 0x80; // Function call
    pub const BPF_EXIT: u8 = 0x90; // Exit program
    pub const BPF_JLT: u8 = 0xa0; // Jump if less than
    pub const BPF_JLE: u8 = 0xb0; // Jump if less or equal
    pub const BPF_JSLT: u8 = 0xc0; // Jump if signed less than
    pub const BPF_JSLE: u8 = 0xd0; // Jump if signed less or equal

    // Memory modes
    pub const BPF_IMM: u8 = 0x00;
    pub const BPF_ABS: u8 = 0x20;
    pub const BPF_IND: u8 = 0x40;
    pub const BPF_MEM: u8 = 0x60;

    // Composite opcodes for common operations
    pub const MOV64_IMM: u8 = BPF_ALU64 | BPF_MOV | BPF_K; // 0xb7
    pub const MOV64_REG: u8 = BPF_ALU64 | BPF_MOV | BPF_X; // 0xbf
    pub const ADD64_IMM: u8 = BPF_ALU64 | BPF_ADD | BPF_K; // 0x07
    pub const ADD64_REG: u8 = BPF_ALU64 | BPF_ADD | BPF_X; // 0x0f
    pub const SUB64_IMM: u8 = BPF_ALU64 | BPF_SUB | BPF_K; // 0x17
    pub const SUB64_REG: u8 = BPF_ALU64 | BPF_SUB | BPF_X; // 0x1f
    pub const MUL64_IMM: u8 = BPF_ALU64 | BPF_MUL | BPF_K; // 0x27
    pub const MUL64_REG: u8 = BPF_ALU64 | BPF_MUL | BPF_X; // 0x2f
    pub const DIV64_IMM: u8 = BPF_ALU64 | BPF_DIV | BPF_K; // 0x37
    pub const DIV64_REG: u8 = BPF_ALU64 | BPF_DIV | BPF_X; // 0x3f
    pub const MOD64_IMM: u8 = BPF_ALU64 | BPF_MOD | BPF_K; // 0x97
    pub const MOD64_REG: u8 = BPF_ALU64 | BPF_MOD | BPF_X; // 0x9f
    pub const OR64_IMM: u8 = BPF_ALU64 | BPF_OR | BPF_K; // 0x47
    pub const OR64_REG: u8 = BPF_ALU64 | BPF_OR | BPF_X; // 0x4f
    pub const AND64_IMM: u8 = BPF_ALU64 | BPF_AND | BPF_K; // 0x57
    pub const AND64_REG: u8 = BPF_ALU64 | BPF_AND | BPF_X; // 0x5f
    pub const XOR64_IMM: u8 = BPF_ALU64 | BPF_XOR | BPF_K; // 0xa7
    pub const XOR64_REG: u8 = BPF_ALU64 | BPF_XOR | BPF_X; // 0xaf
    pub const LSH64_IMM: u8 = BPF_ALU64 | BPF_LSH | BPF_K; // 0x67
    pub const LSH64_REG: u8 = BPF_ALU64 | BPF_LSH | BPF_X; // 0x6f
    pub const RSH64_IMM: u8 = BPF_ALU64 | BPF_RSH | BPF_K; // 0x77
    pub const RSH64_REG: u8 = BPF_ALU64 | BPF_RSH | BPF_X; // 0x7f
    pub const CALL: u8 = BPF_JMP | BPF_CALL; // 0x85
    pub const EXIT: u8 = BPF_JMP | BPF_EXIT; // 0x95
    pub const LD_DW_IMM: u8 = BPF_LD | BPF_DW | BPF_IMM; // 0x18 (64-bit immediate load)
}

/// A single eBPF instruction (64-bit)
#[derive(Debug, Clone, Copy)]
pub struct EbpfInsn {
    /// Operation code
    pub opcode: u8,
    /// Destination register (4 bits, lower nibble)
    pub dst_reg: u8,
    /// Source register (4 bits, upper nibble)
    pub src_reg: u8,
    /// Signed offset for memory/branch operations
    pub offset: i16,
    /// Signed immediate value
    pub imm: i32,
}

impl EbpfInsn {
    /// Create a new instruction
    pub const fn new(opcode: u8, dst_reg: u8, src_reg: u8, offset: i16, imm: i32) -> Self {
        Self {
            opcode,
            dst_reg,
            src_reg,
            offset,
            imm,
        }
    }

    /// Encode the instruction to 8 bytes (little-endian)
    pub fn encode(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0] = self.opcode;
        bytes[1] = (self.src_reg << 4) | (self.dst_reg & 0x0f);
        bytes[2..4].copy_from_slice(&self.offset.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.imm.to_le_bytes());
        bytes
    }

    // ===== Instruction builders =====

    /// MOV64 dst, imm - Load 32-bit immediate into 64-bit register (sign-extends)
    pub const fn mov64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::MOV64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// MOV32 dst, imm - Load 32-bit immediate into lower 32 bits of register (zeros upper bits)
    pub const fn mov32_imm(dst: EbpfReg, imm: i32) -> Self {
        // BPF_ALU (32-bit) | BPF_MOV | BPF_K = 0x04 | 0xb0 | 0x00 = 0xb4
        Self::new(0xb4, dst.as_u8(), 0, 0, imm)
    }

    /// MOV64 dst, src - Copy register
    pub const fn mov64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::MOV64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// ADD64 dst, imm - Add immediate to register
    pub const fn add64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::ADD64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// ADD64 dst, src - Add register to register
    pub const fn add64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::ADD64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// SUB64 dst, imm - Subtract immediate from register
    pub const fn sub64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::SUB64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// SUB64 dst, src - Subtract register from register
    pub const fn sub64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::SUB64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// MUL64 dst, imm - Multiply register by immediate
    pub const fn mul64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::MUL64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// MUL64 dst, src - Multiply register by register
    pub const fn mul64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::MUL64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// DIV64 dst, imm - Divide register by immediate
    pub const fn div64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::DIV64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// DIV64 dst, src - Divide register by register
    pub const fn div64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::DIV64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// MOD64 dst, imm - Modulo register by immediate
    pub const fn mod64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::MOD64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// MOD64 dst, src - Modulo register by register
    pub const fn mod64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::MOD64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// OR64 dst, imm - Bitwise OR register with immediate
    pub const fn or64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::OR64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// OR64 dst, src - Bitwise OR register with register
    pub const fn or64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::OR64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// AND64 dst, imm - Bitwise AND register with immediate
    pub const fn and64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::AND64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// AND32 dst, imm - Bitwise AND lower 32 bits with immediate (zeros upper bits)
    pub const fn and32_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(
            opcode::BPF_ALU | opcode::BPF_AND | opcode::BPF_K,
            dst.as_u8(),
            0,
            0,
            imm,
        )
    }

    /// AND64 dst, src - Bitwise AND register with register
    pub const fn and64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::AND64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// XOR64 dst, imm - Bitwise XOR register with immediate
    pub const fn xor64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::XOR64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// XOR64 dst, src - Bitwise XOR register with register
    pub const fn xor64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::XOR64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// LSH64 dst, imm - Left shift register by immediate
    pub const fn lsh64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::LSH64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// LSH64 dst, src - Left shift register by register
    pub const fn lsh64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::LSH64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// RSH64 dst, imm - Right shift register by immediate
    pub const fn rsh64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::RSH64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// RSH64 dst, src - Right shift register by register
    pub const fn rsh64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::RSH64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// CALL helper - Call a BPF helper function
    pub const fn call(helper: BpfHelper) -> Self {
        Self::new(opcode::CALL, 0, 0, 0, helper as i32)
    }

    /// CALL local - BPF-to-BPF function call (src=1 indicates local call)
    /// The imm field contains the offset to the target function in instructions
    pub const fn call_local(offset: i32) -> Self {
        // src_reg = 1 (BPF_PSEUDO_CALL) indicates this is a local function call
        Self::new(opcode::CALL, 0, 1, 0, offset)
    }

    /// CALL kfunc - BPF kfunc call (src=2 indicates BPF_PSEUDO_KFUNC_CALL)
    /// The imm field contains the kernel BTF ID for a BTF_KIND_FUNC.
    pub const fn call_kfunc(btf_id: i32) -> Self {
        Self::new(opcode::CALL, 0, 2, 0, btf_id)
    }

    /// EXIT - Exit the eBPF program (return value in r0)
    pub const fn exit() -> Self {
        Self::new(opcode::EXIT, 0, 0, 0, 0)
    }

    /// JA offset - Unconditional jump (offset is relative to next instruction)
    pub const fn jump(offset: i16) -> Self {
        Self::new(opcode::BPF_JMP | opcode::BPF_JA, 0, 0, offset, 0)
    }

    /// JNE dst, src, offset - Jump if dst != src (unsigned)
    pub const fn jne_reg(dst: EbpfReg, src: EbpfReg, offset: i16) -> Self {
        Self::new(
            opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_X,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// JEQ dst, imm, offset - Jump if dst == imm
    pub const fn jeq_imm(dst: EbpfReg, imm: i32, offset: i16) -> Self {
        Self::new(
            opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_K,
            dst.as_u8(),
            0,
            offset,
            imm,
        )
    }

    /// JEQ dst, src, offset - Jump if dst == src (register comparison)
    pub const fn jeq_reg(dst: EbpfReg, src: EbpfReg, offset: i16) -> Self {
        Self::new(
            opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_X,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// NEG64 dst - Negate register (dst = -dst)
    pub const fn neg64(dst: EbpfReg) -> Self {
        Self::new(opcode::BPF_ALU64 | opcode::BPF_NEG, dst.as_u8(), 0, 0, 0)
    }

    /// STXDW [dst+off], src - Store 64-bit value from register to memory
    pub const fn stxdw(dst: EbpfReg, offset: i16, src: EbpfReg) -> Self {
        Self::new(
            opcode::BPF_STX | opcode::BPF_DW | opcode::BPF_MEM,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// STXW [dst+off], src - Store 32-bit value from register to memory
    pub const fn stxw(dst: EbpfReg, offset: i16, src: EbpfReg) -> Self {
        Self::new(
            opcode::BPF_STX | opcode::BPF_W | opcode::BPF_MEM,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// STXH [dst+off], src - Store 16-bit value from register to memory
    pub const fn stxh(dst: EbpfReg, offset: i16, src: EbpfReg) -> Self {
        Self::new(
            opcode::BPF_STX | opcode::BPF_H | opcode::BPF_MEM,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// STXB [dst+off], src - Store 8-bit value from register to memory
    pub const fn stxb(dst: EbpfReg, offset: i16, src: EbpfReg) -> Self {
        Self::new(
            opcode::BPF_STX | opcode::BPF_B | opcode::BPF_MEM,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// LDXB dst, [src+off] - Load 8-bit value from memory to register
    pub const fn ldxb(dst: EbpfReg, src: EbpfReg, offset: i16) -> Self {
        Self::new(
            opcode::BPF_LDX | opcode::BPF_B | opcode::BPF_MEM,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// LDXH dst, [src+off] - Load 16-bit value from memory to register
    pub const fn ldxh(dst: EbpfReg, src: EbpfReg, offset: i16) -> Self {
        Self::new(
            opcode::BPF_LDX | opcode::BPF_H | opcode::BPF_MEM,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// LDXW dst, [src+off] - Load 32-bit value from memory to register
    pub const fn ldxw(dst: EbpfReg, src: EbpfReg, offset: i16) -> Self {
        Self::new(
            opcode::BPF_LDX | opcode::BPF_W | opcode::BPF_MEM,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// LDXDW dst, [src+off] - Load 64-bit value from memory to register
    pub const fn ldxdw(dst: EbpfReg, src: EbpfReg, offset: i16) -> Self {
        Self::new(
            opcode::BPF_LDX | opcode::BPF_DW | opcode::BPF_MEM,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// LD_MAP_FD - Load map file descriptor (pseudo instruction, needs relocation)
    /// This creates a 16-byte instruction (two slots) that will be patched by the loader
    pub fn ld_map_fd(dst: EbpfReg) -> [Self; 2] {
        [
            Self::new(
                opcode::LD_DW_IMM,
                dst.as_u8(),
                1, // src_reg=1 means "load map by fd"
                0,
                0, // Will be filled by relocation
            ),
            Self::new(0, 0, 0, 0, 0), // Second half of 128-bit instruction
        ]
    }
}

/// Builder for constructing eBPF programs
#[derive(Debug, Default)]
pub struct EbpfBuilder {
    instructions: Vec<EbpfInsn>,
}

impl EbpfBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an instruction
    pub fn push(&mut self, insn: EbpfInsn) -> &mut Self {
        self.instructions.push(insn);
        self
    }

    /// Get the current instruction count
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Build the raw bytecode
    pub fn build(self) -> Vec<u8> {
        let mut bytecode = Vec::with_capacity(self.instructions.len() * 8);
        for insn in self.instructions {
            bytecode.extend_from_slice(&insn.encode());
        }
        bytecode
    }

    /// Get instructions for inspection
    pub fn instructions(&self) -> &[EbpfInsn] {
        &self.instructions
    }

    /// Set the offset field of an instruction (for fixup of jumps)
    pub fn set_offset(&mut self, idx: usize, offset: i16) {
        if let Some(insn) = self.instructions.get_mut(idx) {
            insn.offset = offset;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mov64_imm_encoding() {
        let insn = EbpfInsn::mov64_imm(EbpfReg::R0, 0);
        let bytes = insn.encode();
        // opcode=0xb7, regs=0x00, offset=0x0000, imm=0x00000000
        assert_eq!(bytes, [0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_mov64_imm_with_value() {
        let insn = EbpfInsn::mov64_imm(EbpfReg::R1, 42);
        let bytes = insn.encode();
        // opcode=0xb7, regs=0x01 (dst=1), offset=0x0000, imm=42
        assert_eq!(bytes, [0xb7, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_exit_encoding() {
        let insn = EbpfInsn::exit();
        let bytes = insn.encode();
        // opcode=0x95
        assert_eq!(bytes, [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_call_helper() {
        let insn = EbpfInsn::call(BpfHelper::TracePrintk);
        let bytes = insn.encode();
        // opcode=0x85, imm=6 (TracePrintk helper number)
        assert_eq!(bytes, [0x85, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_call_kfunc() {
        let insn = EbpfInsn::call_kfunc(1234);
        let bytes = insn.encode();
        // opcode=0x85, src_reg=2 (BPF_PSEUDO_KFUNC_CALL), imm=1234
        assert_eq!(bytes, [0x85, 0x20, 0x00, 0x00, 0xd2, 0x04, 0x00, 0x00]);
    }

    #[test]
    fn test_helper_signature_kptr_xchg() {
        let sig = HelperSignature::for_id(BpfHelper::KptrXchg as u32)
            .expect("expected bpf_kptr_xchg helper signature");
        assert_eq!(sig.min_args, 2);
        assert_eq!(sig.max_args, 2);
        assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
        assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);
    }

    #[test]
    fn test_kfunc_signature_task_from_pid() {
        let sig = KfuncSignature::for_name("bpf_task_from_pid")
            .expect("expected bpf_task_from_pid kfunc signature");
        assert_eq!(sig.min_args, 1);
        assert_eq!(sig.max_args, 1);
        assert_eq!(sig.arg_kind(0), KfuncArgKind::Scalar);
        assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);
    }

    #[test]
    fn test_kfunc_signature_cgroup_release() {
        let sig = KfuncSignature::for_name("bpf_cgroup_release")
            .expect("expected bpf_cgroup_release kfunc signature");
        assert_eq!(sig.min_args, 1);
        assert_eq!(sig.max_args, 1);
        assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
        assert_eq!(sig.ret_kind, KfuncRetKind::Void);
    }

    #[test]
    fn test_kfunc_signature_cpumask_create() {
        let sig = KfuncSignature::for_name("bpf_cpumask_create")
            .expect("expected bpf_cpumask_create kfunc signature");
        assert_eq!(sig.min_args, 0);
        assert_eq!(sig.max_args, 0);
        assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);
    }

    #[test]
    fn test_kfunc_signature_object_impls() {
        let sig = KfuncSignature::for_name("bpf_obj_new_impl")
            .expect("expected bpf_obj_new_impl kfunc signature");
        assert_eq!(sig.min_args, 2);
        assert_eq!(sig.max_args, 2);
        assert_eq!(sig.arg_kind(0), KfuncArgKind::Scalar);
        assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
        assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

        let sig = KfuncSignature::for_name("bpf_obj_drop_impl")
            .expect("expected bpf_obj_drop_impl kfunc signature");
        assert_eq!(sig.min_args, 2);
        assert_eq!(sig.max_args, 2);
        assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
        assert_eq!(sig.ret_kind, KfuncRetKind::Void);

        let sig = KfuncSignature::for_name("bpf_refcount_acquire_impl")
            .expect("expected bpf_refcount_acquire_impl kfunc signature");
        assert_eq!(sig.min_args, 2);
        assert_eq!(sig.max_args, 2);
        assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
        assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);
    }

    #[test]
    fn test_kfunc_signature_file_kfuncs() {
        let sig = KfuncSignature::for_name("bpf_get_task_exe_file")
            .expect("expected bpf_get_task_exe_file kfunc signature");
        assert_eq!(sig.min_args, 1);
        assert_eq!(sig.max_args, 1);
        assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
        assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

        let sig = KfuncSignature::for_name("bpf_put_file")
            .expect("expected bpf_put_file kfunc signature");
        assert_eq!(sig.min_args, 1);
        assert_eq!(sig.max_args, 1);
        assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
        assert_eq!(sig.ret_kind, KfuncRetKind::Void);
    }

    #[test]
    fn test_kfunc_signature_kptr_container_impls() {
        let sig = KfuncSignature::for_name("bpf_percpu_obj_new_impl")
            .expect("expected bpf_percpu_obj_new_impl kfunc signature");
        assert_eq!(sig.min_args, 2);
        assert_eq!(sig.max_args, 2);
        assert_eq!(sig.arg_kind(0), KfuncArgKind::Scalar);
        assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
        assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

        let sig = KfuncSignature::for_name("bpf_list_push_back_impl")
            .expect("expected bpf_list_push_back_impl kfunc signature");
        assert_eq!(sig.min_args, 4);
        assert_eq!(sig.max_args, 4);
        assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
        assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
        assert_eq!(sig.arg_kind(3), KfuncArgKind::Scalar);
        assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

        let sig = KfuncSignature::for_name("bpf_rbtree_first")
            .expect("expected bpf_rbtree_first kfunc signature");
        assert_eq!(sig.min_args, 1);
        assert_eq!(sig.max_args, 1);
        assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
        assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);
    }

    #[test]
    fn test_kfunc_signature_task_vma_iter_kfuncs() {
        let sig = KfuncSignature::for_name("bpf_iter_task_vma_new")
            .expect("expected bpf_iter_task_vma_new kfunc signature");
        assert_eq!(sig.min_args, 3);
        assert_eq!(sig.max_args, 3);
        assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
        assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
        assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

        let sig = KfuncSignature::for_name("bpf_iter_task_vma_next")
            .expect("expected bpf_iter_task_vma_next kfunc signature");
        assert_eq!(sig.min_args, 1);
        assert_eq!(sig.max_args, 1);
        assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
        assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

        let sig = KfuncSignature::for_name("bpf_iter_task_vma_destroy")
            .expect("expected bpf_iter_task_vma_destroy kfunc signature");
        assert_eq!(sig.min_args, 1);
        assert_eq!(sig.max_args, 1);
        assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
        assert_eq!(sig.ret_kind, KfuncRetKind::Void);
    }

    #[test]
    fn test_kfunc_signature_cpumask_and() {
        let sig = KfuncSignature::for_name("bpf_cpumask_and")
            .expect("expected bpf_cpumask_and kfunc signature");
        assert_eq!(sig.min_args, 3);
        assert_eq!(sig.max_args, 3);
        assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
        assert_eq!(sig.arg_kind(2), KfuncArgKind::Pointer);
        assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);
    }

    #[test]
    fn test_kfunc_signature_scx_dsq_insert() {
        let sig = KfuncSignature::for_name("scx_bpf_dsq_insert")
            .expect("expected scx_bpf_dsq_insert kfunc signature");
        assert_eq!(sig.min_args, 4);
        assert_eq!(sig.max_args, 4);
        assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
        assert_eq!(sig.ret_kind, KfuncRetKind::Void);
    }

    #[test]
    fn test_kfunc_ref_kind_mappings() {
        assert_eq!(
            kfunc_acquire_ref_kind("bpf_task_from_pid"),
            Some(KfuncRefKind::Task)
        );
        assert_eq!(
            kfunc_acquire_ref_kind("bpf_cgroup_from_id"),
            Some(KfuncRefKind::Cgroup)
        );
        assert_eq!(
            kfunc_acquire_ref_kind("bpf_get_task_exe_file"),
            Some(KfuncRefKind::File)
        );
        assert_eq!(
            kfunc_acquire_ref_kind("bpf_obj_new_impl"),
            Some(KfuncRefKind::Object)
        );
        assert_eq!(
            kfunc_acquire_ref_kind("bpf_percpu_obj_new_impl"),
            Some(KfuncRefKind::Object)
        );
        assert_eq!(
            kfunc_release_ref_kind("bpf_task_release"),
            Some(KfuncRefKind::Task)
        );
        assert_eq!(
            kfunc_release_ref_kind("bpf_cgroup_release"),
            Some(KfuncRefKind::Cgroup)
        );
        assert_eq!(
            kfunc_release_ref_kind("bpf_put_file"),
            Some(KfuncRefKind::File)
        );
        assert_eq!(
            kfunc_release_ref_kind("bpf_obj_drop_impl"),
            Some(KfuncRefKind::Object)
        );
        assert_eq!(
            kfunc_release_ref_kind("bpf_percpu_obj_drop_impl"),
            Some(KfuncRefKind::Object)
        );
        assert_eq!(
            kfunc_release_ref_kind("bpf_cpumask_release"),
            Some(KfuncRefKind::Cpumask)
        );
    }

    #[test]
    fn test_kfunc_pointer_arg_ref_kind_mappings() {
        assert_eq!(
            kfunc_pointer_arg_ref_kind("bpf_task_under_cgroup", 0),
            Some(KfuncRefKind::Task)
        );
        assert_eq!(
            kfunc_pointer_arg_ref_kind("bpf_get_task_exe_file", 0),
            Some(KfuncRefKind::Task)
        );
        assert_eq!(
            kfunc_pointer_arg_ref_kind("bpf_iter_task_vma_new", 1),
            Some(KfuncRefKind::Task)
        );
        assert_eq!(
            kfunc_pointer_arg_ref_kind("bpf_task_under_cgroup", 1),
            Some(KfuncRefKind::Cgroup)
        );
        assert_eq!(
            kfunc_pointer_arg_ref_kind("bpf_put_file", 0),
            Some(KfuncRefKind::File)
        );
        assert_eq!(
            kfunc_pointer_arg_ref_kind("bpf_obj_drop_impl", 0),
            Some(KfuncRefKind::Object)
        );
        assert_eq!(
            kfunc_pointer_arg_ref_kind("bpf_percpu_obj_drop_impl", 0),
            Some(KfuncRefKind::Object)
        );
        assert_eq!(
            kfunc_pointer_arg_ref_kind("bpf_cpumask_release", 0),
            Some(KfuncRefKind::Cpumask)
        );
        assert_eq!(
            kfunc_pointer_arg_ref_kind("bpf_cpumask_test_cpu", 1),
            Some(KfuncRefKind::Cpumask)
        );
        assert_eq!(
            kfunc_pointer_arg_ref_kind("scx_bpf_task_cpu", 0),
            Some(KfuncRefKind::Task)
        );
        assert_eq!(
            kfunc_pointer_arg_ref_kind("scx_bpf_pick_idle_cpu", 0),
            Some(KfuncRefKind::Cpumask)
        );
        assert_eq!(kfunc_pointer_arg_ref_kind("bpf_task_from_pid", 0), None);
    }

    #[test]
    fn test_kfunc_pointer_arg_requires_kernel_mappings() {
        assert!(kfunc_pointer_arg_requires_kernel("bpf_task_release", 0));
        assert!(kfunc_pointer_arg_requires_kernel("bpf_put_file", 0));
        assert!(kfunc_pointer_arg_requires_kernel(
            "bpf_list_push_front_impl",
            0
        ));
        assert!(kfunc_pointer_arg_requires_kernel(
            "bpf_list_push_front_impl",
            1
        ));
        assert!(kfunc_pointer_arg_requires_kernel("bpf_rbtree_first", 0));
        assert!(kfunc_pointer_arg_requires_kernel("bpf_path_d_path", 0));
        assert!(kfunc_pointer_arg_requires_kernel(
            "bpf_iter_task_vma_new",
            1
        ));
        assert!(!kfunc_pointer_arg_requires_kernel(
            "bpf_iter_task_vma_new",
            0
        ));
        assert!(!kfunc_pointer_arg_requires_kernel(
            "bpf_list_push_front_impl",
            2
        ));
        assert!(!kfunc_pointer_arg_requires_kernel("bpf_obj_new_impl", 1));
    }

    #[test]
    fn test_builder() {
        let mut builder = EbpfBuilder::new();
        builder
            .push(EbpfInsn::mov64_imm(EbpfReg::R0, 0))
            .push(EbpfInsn::exit());

        let bytecode = builder.build();
        assert_eq!(bytecode.len(), 16); // 2 instructions * 8 bytes
    }
}
