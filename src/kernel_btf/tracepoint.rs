//! Tracepoint context information from kernel BTF

use super::types::{FieldInfo, TypeInfo};

const SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL: &str = "4.7";
const SYSCALL_TRACEPOINT_FALLBACK_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.7/include/trace/events/syscalls.h";
const READ_WRITE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c";
const OPEN_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/open.c";
const OPENAT2_MIN_KERNEL: &str = "5.6";
const OPENAT2_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.6/fs/open.c";
const FACCESSAT2_MIN_KERNEL: &str = "5.8";
const FACCESSAT2_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.8/fs/open.c";
const CLOSE_RANGE_MIN_KERNEL: &str = "5.9";
const CLOSE_RANGE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.9/fs/open.c";
const EXEC_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/exec.c";
const EXIT_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/exit.c";
const FORK_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/fork.c";
const CLONE3_MIN_KERNEL: &str = "5.3";
const CLONE3_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.3/kernel/fork.c";
const NSPROXY_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/nsproxy.c";
const FILE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/file.c";
const PIPE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/pipe.c";
const EVENTFD_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/eventfd.c";
const EVENTPOLL_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/eventpoll.c";
const STAT_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/stat.c";
const STATX_MIN_KERNEL: &str = "4.11";
const STATX_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.11/fs/stat.c";
const NAMEI_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c";
const SOCKET_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/net/socket.c";
const X86_MMAP_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/sys_x86_64.c";
const MM_MMAP_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/mmap.c";
const MM_MPROTECT_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/mprotect.c";
const MM_MREMAP_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/mremap.c";
const MM_MADVISE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/madvise.c";
const MM_MLOCK_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/mlock.c";
const MM_MINCORE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/mincore.c";
const MM_MSYNC_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/msync.c";
const MEMFD_CREATE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/shmem.c";
const MEMFD_SECRET_MIN_KERNEL: &str = "5.14";
const MEMFD_SECRET_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.14/mm/secretmem.c";
const PROCESS_MADVISE_MIN_KERNEL: &str = "5.10";
const PROCESS_MADVISE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.10/mm/madvise.c";
const PROCESS_MRELEASE_MIN_KERNEL: &str = "5.15";
const PROCESS_MRELEASE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.15/mm/oom_kill.c";
const TIME_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/time/time.c";
const ITIMER_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/time/itimer.c";
const HRTIMER_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/time/hrtimer.c";
const POSIX_TIMERS_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c";
const TIMERFD_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/timerfd.c";
const IO_URING_MIN_KERNEL: &str = "5.1";
const IO_URING_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.1/fs/io_uring.c";
const SIGNAL_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c";
const PIDFD_SEND_SIGNAL_MIN_KERNEL: &str = "5.1";
const PIDFD_SEND_SIGNAL_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.1/kernel/signal.c";
const PIDFD_OPEN_MIN_KERNEL: &str = "5.3";
const PIDFD_OPEN_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.3/kernel/pid.c";
const PIDFD_GETFD_MIN_KERNEL: &str = "5.6";
const PIDFD_GETFD_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.6/kernel/pid.c";
const KERNEL_SYS_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c";
const GROUPS_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/groups.c";
const CAPABILITY_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/capability.c";
const SCHED_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c";
const FUTEX_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/futex.c";
const IPC_MSG_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/ipc/msg.c";
const IPC_SEM_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/ipc/sem.c";
const IPC_SHM_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/ipc/shm.c";
const WELL_KNOWN_SYS_ENTER_SYSCALLS: &[&str] = &[
    "read",
    "write",
    "close",
    "close_range",
    "open",
    "openat",
    "openat2",
    "creat",
    "access",
    "faccessat",
    "faccessat2",
    "truncate",
    "truncate64",
    "ftruncate",
    "ftruncate64",
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "lchown",
    "fchown",
    "fchownat",
    "execve",
    "execveat",
    "exit",
    "exit_group",
    "waitid",
    "wait4",
    "unshare",
    "clone3",
    "setns",
    "dup",
    "dup2",
    "dup3",
    "pipe",
    "pipe2",
    "eventfd",
    "eventfd2",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "epoll_pwait",
    "stat",
    "lstat",
    "newstat",
    "newlstat",
    "stat64",
    "lstat64",
    "fstat",
    "newfstat",
    "fstat64",
    "newfstatat",
    "fstatat64",
    "statx",
    "mknod",
    "mknodat",
    "mkdir",
    "mkdirat",
    "rmdir",
    "unlink",
    "unlinkat",
    "symlink",
    "symlinkat",
    "link",
    "linkat",
    "rename",
    "renameat",
    "renameat2",
    "socket",
    "socketpair",
    "bind",
    "listen",
    "accept",
    "connect",
    "sendto",
    "recvfrom",
    "accept4",
    "setsockopt",
    "getsockopt",
    "shutdown",
    "sendmsg",
    "recvmsg",
    "sendmmsg",
    "recvmmsg",
    "brk",
    "mmap",
    "mmap_pgoff",
    "old_mmap",
    "munmap",
    "remap_file_pages",
    "mprotect",
    "mremap",
    "madvise",
    "process_madvise",
    "process_mrelease",
    "mlock",
    "mlock2",
    "munlock",
    "mlockall",
    "mincore",
    "msync",
    "memfd_create",
    "memfd_secret",
    "time",
    "gettimeofday",
    "settimeofday",
    "adjtimex",
    "getitimer",
    "setitimer",
    "nanosleep",
    "timer_create",
    "timer_gettime",
    "timer_getoverrun",
    "timer_settime",
    "timer_delete",
    "clock_settime",
    "clock_gettime",
    "clock_adjtime",
    "clock_getres",
    "clock_nanosleep",
    "timerfd_create",
    "timerfd_settime",
    "timerfd_gettime",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "rt_sigprocmask",
    "rt_sigpending",
    "rt_sigtimedwait",
    "kill",
    "tkill",
    "tgkill",
    "rt_sigqueueinfo",
    "rt_tgsigqueueinfo",
    "sigaltstack",
    "rt_sigaction",
    "rt_sigsuspend",
    "pidfd_send_signal",
    "pidfd_open",
    "pidfd_getfd",
    "setpriority",
    "getpriority",
    "setregid",
    "setgid",
    "setreuid",
    "setuid",
    "setresuid",
    "getresuid",
    "setresgid",
    "getresgid",
    "setfsuid",
    "setfsgid",
    "setpgid",
    "getpgid",
    "getsid",
    "sethostname",
    "gethostname",
    "setdomainname",
    "getrlimit",
    "setrlimit",
    "getrusage",
    "umask",
    "prctl",
    "getcpu",
    "getgroups",
    "setgroups",
    "capget",
    "capset",
    "nice",
    "sched_setscheduler",
    "sched_setparam",
    "sched_setattr",
    "sched_getscheduler",
    "sched_getparam",
    "sched_getattr",
    "sched_setaffinity",
    "sched_getaffinity",
    "sched_yield",
    "sched_get_priority_max",
    "sched_get_priority_min",
    "sched_rr_get_interval",
    "futex",
    "msgget",
    "msgctl",
    "msgsnd",
    "msgrcv",
    "semget",
    "semctl",
    "semtimedop",
    "semop",
    "shmget",
    "shmctl",
    "shmat",
    "shmdt",
];
const TRACEPOINT_PRESERVED_FALLBACK_FIELD_NAMES: &[&str] = &[
    "pid",
    "tid",
    "tgid",
    "pid_tgid",
    "current_pid_tgid",
    "uid",
    "gid",
    "uid_gid",
    "current_uid_gid",
    "comm",
    "current_task",
    "current_cgroup",
    "cpu",
    "numa_node",
    "numa_node_id",
    "random",
    "prandom_u32",
    "ktime",
    "timestamp",
    "ktime_boot",
    "boot_ktime",
    "boot_time",
    "ktime_coarse",
    "coarse_ktime",
    "coarse_time",
    "ktime_tai",
    "tai_ktime",
    "tai_time",
    "jiffies",
    "func_ip",
    "function_ip",
    "attach_cookie",
    "bpf_cookie",
    "cgroup_id",
    "arg_count",
    "kstack",
    "ustack",
];

/// Source used to construct a tracepoint context layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TracepointContextSource {
    TracefsFormat,
    WellKnownSyscallFallback,
}

impl TracepointContextSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::TracefsFormat => "tracefs-format",
            Self::WellKnownSyscallFallback => "well-known-syscall-fallback",
        }
    }

    pub fn minimum_kernel(self) -> Option<&'static str> {
        match self {
            Self::TracefsFormat => None,
            // BPF tracepoint programs require Linux 4.7. The syscall tracepoint
            // layout predates that, but 4.7 is the earliest useful eBPF floor.
            Self::WellKnownSyscallFallback => Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
        }
    }

    pub fn minimum_kernel_source(self) -> Option<&'static str> {
        match self {
            Self::TracefsFormat => None,
            Self::WellKnownSyscallFallback => Some(SYSCALL_TRACEPOINT_FALLBACK_SOURCE),
        }
    }
}

/// Tracepoint context layout from kernel BTF
///
/// Tracepoints have structured contexts (not pt_regs like kprobes).
/// The context is a struct named `trace_event_raw_<tracepoint_name>`.
#[derive(Debug, Clone)]
pub struct TracepointContext {
    /// The full struct name (e.g., "trace_event_raw_sys_enter")
    pub struct_name: String,
    /// The tracepoint category (e.g., "syscalls")
    pub category: String,
    /// The tracepoint name (e.g., "sys_enter_openat")
    pub name: String,
    /// Available fields in the context
    pub fields: Vec<FieldInfo>,
    /// Total size of the context struct
    pub size: usize,
    /// Where the layout metadata came from.
    pub source: TracepointContextSource,
    /// Path to the tracefs format file when this layout was read from tracefs.
    pub source_path: Option<String>,
    /// Compatibility floor for this specific tracepoint layout, when known.
    pub minimum_kernel: Option<&'static str>,
    /// Source for the compatibility floor.
    pub minimum_kernel_source: Option<&'static str>,
}

impl TracepointContext {
    /// Create a new tracepoint context
    pub fn new(
        category: impl Into<String>,
        name: impl Into<String>,
        struct_name: impl Into<String>,
        fields: Vec<FieldInfo>,
        size: usize,
    ) -> Self {
        Self::new_with_source(
            category,
            name,
            struct_name,
            fields,
            size,
            TracepointContextSource::TracefsFormat,
            None,
        )
    }

    /// Create a new tracepoint context with explicit provenance.
    pub fn new_with_source(
        category: impl Into<String>,
        name: impl Into<String>,
        struct_name: impl Into<String>,
        fields: Vec<FieldInfo>,
        size: usize,
        source: TracepointContextSource,
        source_path: Option<String>,
    ) -> Self {
        Self::new_with_source_and_minimum_kernel(
            category,
            name,
            struct_name,
            fields,
            size,
            source,
            source_path,
            source.minimum_kernel(),
            source.minimum_kernel_source(),
        )
    }

    /// Create a new tracepoint context with explicit provenance and compatibility metadata.
    pub fn new_with_source_and_minimum_kernel(
        category: impl Into<String>,
        name: impl Into<String>,
        struct_name: impl Into<String>,
        fields: Vec<FieldInfo>,
        size: usize,
        source: TracepointContextSource,
        source_path: Option<String>,
        minimum_kernel: Option<&'static str>,
        minimum_kernel_source: Option<&'static str>,
    ) -> Self {
        Self {
            category: category.into(),
            name: name.into(),
            struct_name: struct_name.into(),
            fields,
            size,
            source,
            source_path,
            minimum_kernel,
            minimum_kernel_source,
        }
    }

    /// Minimum kernel for the specific tracepoint, including syscall existence
    /// when the layout came from a well-known syscall fallback.
    pub fn minimum_kernel(&self) -> Option<&'static str> {
        self.minimum_kernel
    }

    /// Source for the specific tracepoint compatibility floor.
    pub fn minimum_kernel_source(&self) -> Option<&'static str> {
        self.minimum_kernel_source
    }

    /// Get a field by name
    pub fn get_field(&self, name: &str) -> Option<&FieldInfo> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Check if a field exists
    pub fn has_field(&self, name: &str) -> bool {
        self.fields.iter().any(|f| f.name == name)
    }

    /// Get field names for error messages
    pub fn field_names(&self) -> Vec<&str> {
        self.fields.iter().map(|f| f.name.as_str()).collect()
    }

    /// Syscalls with source-backed well-known `sys_enter_*` fallback metadata.
    pub fn well_known_sys_enter_syscalls() -> &'static [&'static str] {
        WELL_KNOWN_SYS_ENTER_SYSCALLS
    }
}

/// Well-known syscall tracepoint contexts
///
/// These are fallback definitions for common tracepoints when BTF lookup fails.
/// Based on kernel's include/trace/events/syscalls.h
impl TracepointContext {
    /// Create context for sys_enter tracepoints
    ///
    /// Layout: trace_event_raw_sys_enter { trace_entry ent; long id; unsigned long args[6]; }
    pub fn sys_enter(name: &str) -> Self {
        // trace_entry is 8 bytes (type u16 + flags u8 + preempt_count u8 + pid i32)
        // Then: id (8 bytes), args[6] (48 bytes)
        let mut fields = vec![
            FieldInfo {
                name: "id".into(),
                type_info: TypeInfo::Int {
                    size: 8,
                    signed: true,
                },
                offset: 8, // After trace_entry
                size: 8,
                bitfield: None,
            },
            FieldInfo {
                name: "args".into(),
                type_info: TypeInfo::Array {
                    element: Box::new(TypeInfo::Int {
                        size: 8,
                        signed: false,
                    }),
                    len: 6,
                },
                offset: 16, // After id
                size: 48,
                bitfield: None,
            },
        ];
        fields.extend(Self::well_known_sys_enter_arg_fields(name));

        let (minimum_kernel, minimum_kernel_source) = Self::syscall_fallback_minimum_kernel(name);

        Self::new_with_source_and_minimum_kernel(
            "syscalls",
            name,
            format!("trace_event_raw_{}", name),
            fields,
            64, // 8 + 8 + 48
            TracepointContextSource::WellKnownSyscallFallback,
            None,
            minimum_kernel,
            minimum_kernel_source,
        )
    }

    fn syscall_fallback_minimum_kernel(name: &str) -> (Option<&'static str>, Option<&'static str>) {
        let syscall = name
            .strip_prefix("sys_enter_")
            .or_else(|| name.strip_prefix("sys_exit_"));
        match syscall {
            Some("openat2") => (Some(OPENAT2_MIN_KERNEL), Some(OPENAT2_SOURCE)),
            Some("faccessat2") => (Some(FACCESSAT2_MIN_KERNEL), Some(FACCESSAT2_SOURCE)),
            Some("close_range") => (Some(CLOSE_RANGE_MIN_KERNEL), Some(CLOSE_RANGE_SOURCE)),
            Some("statx") => (Some(STATX_MIN_KERNEL), Some(STATX_SOURCE)),
            Some("clone3") => (Some(CLONE3_MIN_KERNEL), Some(CLONE3_SOURCE)),
            Some("io_uring_setup" | "io_uring_enter" | "io_uring_register") => {
                (Some(IO_URING_MIN_KERNEL), Some(IO_URING_SOURCE))
            }
            Some("memfd_secret") => (Some(MEMFD_SECRET_MIN_KERNEL), Some(MEMFD_SECRET_SOURCE)),
            Some("process_madvise") => (
                Some(PROCESS_MADVISE_MIN_KERNEL),
                Some(PROCESS_MADVISE_SOURCE),
            ),
            Some("process_mrelease") => (
                Some(PROCESS_MRELEASE_MIN_KERNEL),
                Some(PROCESS_MRELEASE_SOURCE),
            ),
            Some("pidfd_send_signal") => (
                Some(PIDFD_SEND_SIGNAL_MIN_KERNEL),
                Some(PIDFD_SEND_SIGNAL_SOURCE),
            ),
            Some("pidfd_open") => (Some(PIDFD_OPEN_MIN_KERNEL), Some(PIDFD_OPEN_SOURCE)),
            Some("pidfd_getfd") => (Some(PIDFD_GETFD_MIN_KERNEL), Some(PIDFD_GETFD_SOURCE)),
            _ => (
                Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
                Some(SYSCALL_TRACEPOINT_FALLBACK_SOURCE),
            ),
        }
    }

    /// Source-backed compatibility floor for well-known syscall fallback fields.
    pub fn syscall_fallback_field_minimum_kernel(
        category: &str,
        name: &str,
        field: &str,
    ) -> Option<(&'static str, &'static str)> {
        if category != "syscalls" {
            return None;
        }

        if let Some(floor) = Self::syscall_fallback_common_field_minimum_kernel(name, field) {
            return Some(floor);
        }

        Self::sys_enter_named_field_minimum_kernel(name, field)
    }

    fn syscall_fallback_common_field_minimum_kernel(
        name: &str,
        field: &str,
    ) -> Option<(&'static str, &'static str)> {
        let syscall = if name.starts_with("sys_enter_") {
            if !matches!(field, "id" | "args") {
                return None;
            }
            name.strip_prefix("sys_enter_")
        } else if name.starts_with("sys_exit_") {
            if !matches!(field, "id" | "ret") {
                return None;
            }
            name.strip_prefix("sys_exit_")
        } else {
            return None;
        }?;

        Some(match syscall {
            "openat2" => (OPENAT2_MIN_KERNEL, OPENAT2_SOURCE),
            "faccessat2" => (FACCESSAT2_MIN_KERNEL, FACCESSAT2_SOURCE),
            "close_range" => (CLOSE_RANGE_MIN_KERNEL, CLOSE_RANGE_SOURCE),
            "statx" => (STATX_MIN_KERNEL, STATX_SOURCE),
            "clone3" => (CLONE3_MIN_KERNEL, CLONE3_SOURCE),
            "io_uring_setup" | "io_uring_enter" | "io_uring_register" => {
                (IO_URING_MIN_KERNEL, IO_URING_SOURCE)
            }
            "memfd_secret" => (MEMFD_SECRET_MIN_KERNEL, MEMFD_SECRET_SOURCE),
            "process_madvise" => (PROCESS_MADVISE_MIN_KERNEL, PROCESS_MADVISE_SOURCE),
            "process_mrelease" => (PROCESS_MRELEASE_MIN_KERNEL, PROCESS_MRELEASE_SOURCE),
            "pidfd_send_signal" => (PIDFD_SEND_SIGNAL_MIN_KERNEL, PIDFD_SEND_SIGNAL_SOURCE),
            "pidfd_open" => (PIDFD_OPEN_MIN_KERNEL, PIDFD_OPEN_SOURCE),
            "pidfd_getfd" => (PIDFD_GETFD_MIN_KERNEL, PIDFD_GETFD_SOURCE),
            _ => (
                SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL,
                SYSCALL_TRACEPOINT_FALLBACK_SOURCE,
            ),
        })
    }

    fn sys_enter_named_field_minimum_kernel(
        name: &str,
        field: &str,
    ) -> Option<(&'static str, &'static str)> {
        let syscall = name.strip_prefix("sys_enter_")?;
        if !Self::well_known_sys_enter_arg_fields(name)
            .iter()
            .any(|arg_field| arg_field.name == field)
        {
            return None;
        }

        Some(match syscall {
            "read" | "write" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, READ_WRITE_SOURCE),
            "close" | "open" | "creat" | "access" | "faccessat" | "truncate" | "truncate64"
            | "ftruncate" | "ftruncate64" | "chmod" | "fchmod" | "fchmodat" | "chown"
            | "lchown" | "fchown" | "fchownat" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, OPEN_SOURCE)
            }
            "openat" => (
                SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL,
                SYSCALL_TRACEPOINT_FALLBACK_SOURCE,
            ),
            "openat2" => (OPENAT2_MIN_KERNEL, OPENAT2_SOURCE),
            "faccessat2" => (FACCESSAT2_MIN_KERNEL, FACCESSAT2_SOURCE),
            "close_range" => (CLOSE_RANGE_MIN_KERNEL, CLOSE_RANGE_SOURCE),
            "execve" | "execveat" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, EXEC_SOURCE),
            "exit" | "exit_group" | "waitid" | "wait4" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, EXIT_SOURCE)
            }
            "unshare" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, FORK_SOURCE),
            "clone3" => (CLONE3_MIN_KERNEL, CLONE3_SOURCE),
            "setns" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, NSPROXY_SOURCE),
            "dup" | "dup2" | "dup3" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, FILE_SOURCE),
            "pipe" | "pipe2" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, PIPE_SOURCE),
            "eventfd" | "eventfd2" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, EVENTFD_SOURCE),
            "epoll_create" | "epoll_create1" | "epoll_ctl" | "epoll_wait" | "epoll_pwait" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, EVENTPOLL_SOURCE)
            }
            "stat" | "lstat" | "newstat" | "newlstat" | "stat64" | "lstat64" | "fstat"
            | "newfstat" | "fstat64" | "newfstatat" | "fstatat64" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, STAT_SOURCE)
            }
            "statx" => (STATX_MIN_KERNEL, STATX_SOURCE),
            "mknod" | "mknodat" | "mkdir" | "mkdirat" | "rmdir" | "unlink" | "unlinkat"
            | "symlink" | "symlinkat" | "link" | "linkat" | "rename" | "renameat" | "renameat2" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, NAMEI_SOURCE)
            }
            "socket" | "socketpair" | "bind" | "listen" | "accept" | "connect" | "sendto"
            | "recvfrom" | "accept4" | "setsockopt" | "getsockopt" | "shutdown" | "sendmsg"
            | "recvmsg" | "sendmmsg" | "recvmmsg" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, SOCKET_SOURCE)
            }
            "mmap" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, X86_MMAP_SOURCE),
            "brk" | "mmap_pgoff" | "old_mmap" | "munmap" | "remap_file_pages" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MM_MMAP_SOURCE)
            }
            "mprotect" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MM_MPROTECT_SOURCE),
            "mremap" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MM_MREMAP_SOURCE),
            "madvise" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MM_MADVISE_SOURCE),
            "process_madvise" => (PROCESS_MADVISE_MIN_KERNEL, PROCESS_MADVISE_SOURCE),
            "process_mrelease" => (PROCESS_MRELEASE_MIN_KERNEL, PROCESS_MRELEASE_SOURCE),
            "mlock" | "mlock2" | "munlock" | "mlockall" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MM_MLOCK_SOURCE)
            }
            "mincore" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MM_MINCORE_SOURCE),
            "msync" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MM_MSYNC_SOURCE),
            "memfd_create" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MEMFD_CREATE_SOURCE),
            "memfd_secret" => (MEMFD_SECRET_MIN_KERNEL, MEMFD_SECRET_SOURCE),
            "time" | "gettimeofday" | "settimeofday" | "adjtimex" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, TIME_SOURCE)
            }
            "getitimer" | "setitimer" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, ITIMER_SOURCE),
            "nanosleep" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, HRTIMER_SOURCE),
            "timer_create" | "timer_gettime" | "timer_getoverrun" | "timer_settime"
            | "timer_delete" | "clock_settime" | "clock_gettime" | "clock_adjtime"
            | "clock_getres" | "clock_nanosleep" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, POSIX_TIMERS_SOURCE)
            }
            "timerfd_create" | "timerfd_settime" | "timerfd_gettime" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, TIMERFD_SOURCE)
            }
            "io_uring_setup" | "io_uring_enter" | "io_uring_register" => {
                (IO_URING_MIN_KERNEL, IO_URING_SOURCE)
            }
            "rt_sigprocmask" | "rt_sigpending" | "rt_sigtimedwait" | "kill" | "tgkill"
            | "tkill" | "rt_sigqueueinfo" | "rt_tgsigqueueinfo" | "sigaltstack"
            | "rt_sigaction" | "rt_sigsuspend" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, SIGNAL_SOURCE)
            }
            "pidfd_send_signal" => (PIDFD_SEND_SIGNAL_MIN_KERNEL, PIDFD_SEND_SIGNAL_SOURCE),
            "pidfd_open" => (PIDFD_OPEN_MIN_KERNEL, PIDFD_OPEN_SOURCE),
            "pidfd_getfd" => (PIDFD_GETFD_MIN_KERNEL, PIDFD_GETFD_SOURCE),
            "setpriority" | "getpriority" | "setregid" | "setgid" | "setreuid" | "setuid"
            | "setresuid" | "getresuid" | "setresgid" | "getresgid" | "setfsuid" | "setfsgid"
            | "setpgid" | "getpgid" | "getsid" | "sethostname" | "gethostname"
            | "setdomainname" | "getrlimit" | "setrlimit" | "getrusage" | "umask" | "prctl"
            | "getcpu" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, KERNEL_SYS_SOURCE),
            "getgroups" | "setgroups" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, GROUPS_SOURCE),
            "capget" | "capset" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, CAPABILITY_SOURCE),
            "nice"
            | "sched_setscheduler"
            | "sched_setparam"
            | "sched_setattr"
            | "sched_getscheduler"
            | "sched_getparam"
            | "sched_getattr"
            | "sched_setaffinity"
            | "sched_getaffinity"
            | "sched_yield"
            | "sched_get_priority_max"
            | "sched_get_priority_min"
            | "sched_rr_get_interval" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, SCHED_SOURCE),
            "futex" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, FUTEX_SOURCE),
            "msgget" | "msgctl" | "msgsnd" | "msgrcv" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, IPC_MSG_SOURCE)
            }
            "semget" | "semctl" | "semtimedop" | "semop" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, IPC_SEM_SOURCE)
            }
            "shmget" | "shmctl" | "shmat" | "shmdt" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, IPC_SHM_SOURCE)
            }
            _ => return None,
        })
    }

    fn sys_enter_arg_field(index: usize, name: &str, type_info: TypeInfo) -> Option<FieldInfo> {
        if index >= 6 {
            return None;
        }
        Some(FieldInfo {
            name: name.into(),
            type_info,
            offset: 16 + index * 8,
            size: 8,
            bitfield: None,
        })
    }

    fn syscall_arg_int(signed: bool) -> TypeInfo {
        TypeInfo::Int { size: 8, signed }
    }

    fn syscall_arg_user_ptr() -> TypeInfo {
        TypeInfo::Ptr {
            target: Box::new(TypeInfo::Unknown),
            is_user: true,
        }
    }

    fn sys_enter_arg_field_name_is_reachable(name: &str) -> bool {
        if name == "arg" || TRACEPOINT_PRESERVED_FALLBACK_FIELD_NAMES.contains(&name) {
            return false;
        }

        !name.strip_prefix("arg").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit())
        })
    }

    fn well_known_sys_enter_arg_fields(name: &str) -> Vec<FieldInfo> {
        let Some(syscall) = name.strip_prefix("sys_enter_") else {
            return Vec::new();
        };

        let fields: Vec<(&str, TypeInfo)> = match syscall {
            "read" | "write" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("buf", Self::syscall_arg_user_ptr()),
                ("count", Self::syscall_arg_int(false)),
            ],
            "close" => vec![("fd", Self::syscall_arg_int(false))],
            "close_range" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("max_fd", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "open" => vec![
                ("filename", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
                ("mode", Self::syscall_arg_int(false)),
            ],
            "openat" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
                ("mode", Self::syscall_arg_int(false)),
            ],
            "openat2" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("how", Self::syscall_arg_user_ptr()),
                ("usize", Self::syscall_arg_int(false)),
            ],
            "creat" => vec![
                ("pathname", Self::syscall_arg_user_ptr()),
                ("mode", Self::syscall_arg_int(false)),
            ],
            "access" => vec![
                ("filename", Self::syscall_arg_user_ptr()),
                ("mode", Self::syscall_arg_int(true)),
            ],
            "faccessat" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("mode", Self::syscall_arg_int(true)),
            ],
            "faccessat2" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("mode", Self::syscall_arg_int(true)),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "truncate" | "truncate64" => vec![
                ("path", Self::syscall_arg_user_ptr()),
                ("length", Self::syscall_arg_int(true)),
            ],
            "ftruncate" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("length", Self::syscall_arg_int(false)),
            ],
            "ftruncate64" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("length", Self::syscall_arg_int(true)),
            ],
            "chmod" => vec![
                ("filename", Self::syscall_arg_user_ptr()),
                ("mode", Self::syscall_arg_int(false)),
            ],
            "fchmod" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("mode", Self::syscall_arg_int(false)),
            ],
            "fchmodat" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("mode", Self::syscall_arg_int(false)),
            ],
            "chown" | "lchown" => vec![
                ("filename", Self::syscall_arg_user_ptr()),
                ("user", Self::syscall_arg_int(false)),
                ("group", Self::syscall_arg_int(false)),
            ],
            "fchown" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("user", Self::syscall_arg_int(false)),
                ("group", Self::syscall_arg_int(false)),
            ],
            "fchownat" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("user", Self::syscall_arg_int(false)),
                ("group", Self::syscall_arg_int(false)),
                ("flag", Self::syscall_arg_int(true)),
            ],
            "execve" => vec![
                ("filename", Self::syscall_arg_user_ptr()),
                ("argv", Self::syscall_arg_user_ptr()),
                ("envp", Self::syscall_arg_user_ptr()),
            ],
            "execveat" => vec![
                ("fd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("argv", Self::syscall_arg_user_ptr()),
                ("envp", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "exit" | "exit_group" => {
                vec![("error_code", Self::syscall_arg_int(true))]
            }
            "waitid" => vec![
                ("which", Self::syscall_arg_int(true)),
                ("upid", Self::syscall_arg_int(true)),
                ("infop", Self::syscall_arg_user_ptr()),
                ("options", Self::syscall_arg_int(true)),
                ("ru", Self::syscall_arg_user_ptr()),
            ],
            "wait4" => vec![
                ("upid", Self::syscall_arg_int(true)),
                ("stat_addr", Self::syscall_arg_user_ptr()),
                ("options", Self::syscall_arg_int(true)),
                ("ru", Self::syscall_arg_user_ptr()),
            ],
            "unshare" => vec![("unshare_flags", Self::syscall_arg_int(false))],
            "clone3" => vec![
                ("uargs", Self::syscall_arg_user_ptr()),
                ("size", Self::syscall_arg_int(false)),
            ],
            "setns" => vec![
                ("fd", Self::syscall_arg_int(true)),
                ("nstype", Self::syscall_arg_int(true)),
            ],
            "dup" => vec![("fildes", Self::syscall_arg_int(false))],
            "dup2" => vec![
                ("oldfd", Self::syscall_arg_int(false)),
                ("newfd", Self::syscall_arg_int(false)),
            ],
            "dup3" => vec![
                ("oldfd", Self::syscall_arg_int(false)),
                ("newfd", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "pipe" => vec![("fildes", Self::syscall_arg_user_ptr())],
            "pipe2" => vec![
                ("fildes", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "eventfd" => vec![("count", Self::syscall_arg_int(false))],
            "eventfd2" => vec![
                ("count", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "epoll_create" => vec![("size", Self::syscall_arg_int(true))],
            "epoll_create1" => vec![("flags", Self::syscall_arg_int(true))],
            "epoll_ctl" => vec![
                ("epfd", Self::syscall_arg_int(true)),
                ("op", Self::syscall_arg_int(true)),
                ("fd", Self::syscall_arg_int(true)),
                ("event", Self::syscall_arg_user_ptr()),
            ],
            "epoll_wait" => vec![
                ("epfd", Self::syscall_arg_int(true)),
                ("events", Self::syscall_arg_user_ptr()),
                ("maxevents", Self::syscall_arg_int(true)),
                ("timeout", Self::syscall_arg_int(true)),
            ],
            "epoll_pwait" => vec![
                ("epfd", Self::syscall_arg_int(true)),
                ("events", Self::syscall_arg_user_ptr()),
                ("maxevents", Self::syscall_arg_int(true)),
                ("timeout", Self::syscall_arg_int(true)),
                ("sigmask", Self::syscall_arg_user_ptr()),
                ("sigsetsize", Self::syscall_arg_int(false)),
            ],
            "stat" | "lstat" | "newstat" | "newlstat" | "stat64" | "lstat64" => vec![
                ("filename", Self::syscall_arg_user_ptr()),
                ("statbuf", Self::syscall_arg_user_ptr()),
            ],
            "fstat" | "newfstat" | "fstat64" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("statbuf", Self::syscall_arg_user_ptr()),
            ],
            "newfstatat" | "fstatat64" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("statbuf", Self::syscall_arg_user_ptr()),
                ("flag", Self::syscall_arg_int(true)),
            ],
            "statx" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
                ("mask", Self::syscall_arg_int(false)),
                ("buffer", Self::syscall_arg_user_ptr()),
            ],
            "mknod" => vec![
                ("filename", Self::syscall_arg_user_ptr()),
                ("mode", Self::syscall_arg_int(false)),
                ("dev", Self::syscall_arg_int(false)),
            ],
            "mknodat" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("mode", Self::syscall_arg_int(false)),
                ("dev", Self::syscall_arg_int(false)),
            ],
            "mkdir" => vec![
                ("pathname", Self::syscall_arg_user_ptr()),
                ("mode", Self::syscall_arg_int(false)),
            ],
            "mkdirat" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("pathname", Self::syscall_arg_user_ptr()),
                ("mode", Self::syscall_arg_int(false)),
            ],
            "rmdir" | "unlink" => vec![("pathname", Self::syscall_arg_user_ptr())],
            "unlinkat" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("pathname", Self::syscall_arg_user_ptr()),
                ("flag", Self::syscall_arg_int(true)),
            ],
            "symlink" | "link" | "rename" => vec![
                ("oldname", Self::syscall_arg_user_ptr()),
                ("newname", Self::syscall_arg_user_ptr()),
            ],
            "symlinkat" => vec![
                ("oldname", Self::syscall_arg_user_ptr()),
                ("newdfd", Self::syscall_arg_int(true)),
                ("newname", Self::syscall_arg_user_ptr()),
            ],
            "linkat" => vec![
                ("olddfd", Self::syscall_arg_int(true)),
                ("oldname", Self::syscall_arg_user_ptr()),
                ("newdfd", Self::syscall_arg_int(true)),
                ("newname", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "renameat" => vec![
                ("olddfd", Self::syscall_arg_int(true)),
                ("oldname", Self::syscall_arg_user_ptr()),
                ("newdfd", Self::syscall_arg_int(true)),
                ("newname", Self::syscall_arg_user_ptr()),
            ],
            "renameat2" => vec![
                ("olddfd", Self::syscall_arg_int(true)),
                ("oldname", Self::syscall_arg_user_ptr()),
                ("newdfd", Self::syscall_arg_int(true)),
                ("newname", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "socket" => vec![
                ("family", Self::syscall_arg_int(false)),
                ("type", Self::syscall_arg_int(false)),
                ("protocol", Self::syscall_arg_int(false)),
            ],
            "socketpair" => vec![
                ("family", Self::syscall_arg_int(false)),
                ("type", Self::syscall_arg_int(false)),
                ("protocol", Self::syscall_arg_int(false)),
                ("usockvec", Self::syscall_arg_user_ptr()),
            ],
            "bind" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("umyaddr", Self::syscall_arg_user_ptr()),
                ("addrlen", Self::syscall_arg_int(false)),
            ],
            "listen" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("backlog", Self::syscall_arg_int(false)),
            ],
            "accept" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("upeer_sockaddr", Self::syscall_arg_user_ptr()),
                ("upeer_addrlen", Self::syscall_arg_user_ptr()),
            ],
            "connect" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("uservaddr", Self::syscall_arg_user_ptr()),
                ("addrlen", Self::syscall_arg_int(false)),
            ],
            "sendto" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("buff", Self::syscall_arg_user_ptr()),
                ("len", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
                ("addr", Self::syscall_arg_user_ptr()),
                ("addr_len", Self::syscall_arg_int(false)),
            ],
            "recvfrom" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("ubuf", Self::syscall_arg_user_ptr()),
                ("size", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
                ("addr", Self::syscall_arg_user_ptr()),
                ("addr_len", Self::syscall_arg_user_ptr()),
            ],
            "accept4" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("upeer_sockaddr", Self::syscall_arg_user_ptr()),
                ("upeer_addrlen", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "setsockopt" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("level", Self::syscall_arg_int(false)),
                ("optname", Self::syscall_arg_int(false)),
                ("optval", Self::syscall_arg_user_ptr()),
                ("optlen", Self::syscall_arg_int(false)),
            ],
            "getsockopt" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("level", Self::syscall_arg_int(false)),
                ("optname", Self::syscall_arg_int(false)),
                ("optval", Self::syscall_arg_user_ptr()),
                ("optlen", Self::syscall_arg_user_ptr()),
            ],
            "shutdown" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("how", Self::syscall_arg_int(false)),
            ],
            "sendmsg" | "recvmsg" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("msg", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "sendmmsg" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("mmsg", Self::syscall_arg_user_ptr()),
                ("vlen", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "recvmmsg" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("mmsg", Self::syscall_arg_user_ptr()),
                ("vlen", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
                ("timeout", Self::syscall_arg_user_ptr()),
            ],
            "brk" => vec![("brk", Self::syscall_arg_int(false))],
            "mmap" => vec![
                ("addr", Self::syscall_arg_int(false)),
                ("len", Self::syscall_arg_int(false)),
                ("prot", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
                ("fd", Self::syscall_arg_int(false)),
                ("off", Self::syscall_arg_int(false)),
            ],
            "mmap_pgoff" => vec![
                ("addr", Self::syscall_arg_int(false)),
                ("len", Self::syscall_arg_int(false)),
                ("prot", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
                ("fd", Self::syscall_arg_int(false)),
                ("pgoff", Self::syscall_arg_int(false)),
            ],
            "old_mmap" => vec![("arg", Self::syscall_arg_user_ptr())],
            "munmap" => vec![
                ("addr", Self::syscall_arg_int(false)),
                ("len", Self::syscall_arg_int(false)),
            ],
            "remap_file_pages" => vec![
                ("start", Self::syscall_arg_int(false)),
                ("size", Self::syscall_arg_int(false)),
                ("prot", Self::syscall_arg_int(false)),
                ("pgoff", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "mprotect" => vec![
                ("start", Self::syscall_arg_int(false)),
                ("len", Self::syscall_arg_int(false)),
                ("prot", Self::syscall_arg_int(false)),
            ],
            "mremap" => vec![
                ("addr", Self::syscall_arg_int(false)),
                ("old_len", Self::syscall_arg_int(false)),
                ("new_len", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
                ("new_addr", Self::syscall_arg_int(false)),
            ],
            "madvise" => vec![
                ("start", Self::syscall_arg_int(false)),
                ("len_in", Self::syscall_arg_int(false)),
                ("behavior", Self::syscall_arg_int(true)),
            ],
            "process_madvise" => vec![
                ("pidfd", Self::syscall_arg_int(true)),
                ("vec", Self::syscall_arg_user_ptr()),
                ("vlen", Self::syscall_arg_int(false)),
                ("behavior", Self::syscall_arg_int(true)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "process_mrelease" => vec![
                ("pidfd", Self::syscall_arg_int(true)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "mlock" | "munlock" => vec![
                ("start", Self::syscall_arg_int(false)),
                ("len", Self::syscall_arg_int(false)),
            ],
            "mlock2" => vec![
                ("start", Self::syscall_arg_int(false)),
                ("len", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "mlockall" => vec![("flags", Self::syscall_arg_int(true))],
            "mincore" => vec![
                ("start", Self::syscall_arg_int(false)),
                ("len", Self::syscall_arg_int(false)),
                ("vec", Self::syscall_arg_user_ptr()),
            ],
            "msync" => vec![
                ("start", Self::syscall_arg_int(false)),
                ("len", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "memfd_create" => vec![
                ("uname", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "memfd_secret" => vec![("flags", Self::syscall_arg_int(false))],
            "time" => vec![("tloc", Self::syscall_arg_user_ptr())],
            "gettimeofday" | "settimeofday" => vec![
                ("tv", Self::syscall_arg_user_ptr()),
                ("tz", Self::syscall_arg_user_ptr()),
            ],
            "adjtimex" => vec![("txc_p", Self::syscall_arg_user_ptr())],
            "getitimer" => vec![
                ("which", Self::syscall_arg_int(true)),
                ("value", Self::syscall_arg_user_ptr()),
            ],
            "setitimer" => vec![
                ("which", Self::syscall_arg_int(true)),
                ("value", Self::syscall_arg_user_ptr()),
                ("ovalue", Self::syscall_arg_user_ptr()),
            ],
            "nanosleep" => vec![
                ("rqtp", Self::syscall_arg_user_ptr()),
                ("rmtp", Self::syscall_arg_user_ptr()),
            ],
            "timer_create" => vec![
                ("which_clock", Self::syscall_arg_int(true)),
                ("timer_event_spec", Self::syscall_arg_user_ptr()),
                ("created_timer_id", Self::syscall_arg_user_ptr()),
            ],
            "timer_gettime" => vec![
                ("timer_id", Self::syscall_arg_int(true)),
                ("setting", Self::syscall_arg_user_ptr()),
            ],
            "timer_getoverrun" | "timer_delete" => {
                vec![("timer_id", Self::syscall_arg_int(true))]
            }
            "timer_settime" => vec![
                ("timer_id", Self::syscall_arg_int(true)),
                ("flags", Self::syscall_arg_int(true)),
                ("new_setting", Self::syscall_arg_user_ptr()),
                ("old_setting", Self::syscall_arg_user_ptr()),
            ],
            "clock_settime" | "clock_gettime" | "clock_getres" => vec![
                ("which_clock", Self::syscall_arg_int(true)),
                ("tp", Self::syscall_arg_user_ptr()),
            ],
            "clock_adjtime" => vec![
                ("which_clock", Self::syscall_arg_int(true)),
                ("utx", Self::syscall_arg_user_ptr()),
            ],
            "clock_nanosleep" => vec![
                ("which_clock", Self::syscall_arg_int(true)),
                ("flags", Self::syscall_arg_int(true)),
                ("rqtp", Self::syscall_arg_user_ptr()),
                ("rmtp", Self::syscall_arg_user_ptr()),
            ],
            "timerfd_create" => vec![
                ("clockid", Self::syscall_arg_int(true)),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "timerfd_settime" => vec![
                ("ufd", Self::syscall_arg_int(true)),
                ("flags", Self::syscall_arg_int(true)),
                ("utmr", Self::syscall_arg_user_ptr()),
                ("otmr", Self::syscall_arg_user_ptr()),
            ],
            "timerfd_gettime" => vec![
                ("ufd", Self::syscall_arg_int(true)),
                ("otmr", Self::syscall_arg_user_ptr()),
            ],
            "io_uring_setup" => vec![
                ("entries", Self::syscall_arg_int(false)),
                ("params", Self::syscall_arg_user_ptr()),
            ],
            "io_uring_enter" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("to_submit", Self::syscall_arg_int(false)),
                ("min_complete", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
                ("sig", Self::syscall_arg_user_ptr()),
                ("sigsz", Self::syscall_arg_int(false)),
            ],
            "io_uring_register" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("opcode", Self::syscall_arg_int(false)),
                ("arg", Self::syscall_arg_user_ptr()),
                ("nr_args", Self::syscall_arg_int(false)),
            ],
            "rt_sigprocmask" => vec![
                ("how", Self::syscall_arg_int(true)),
                ("nset", Self::syscall_arg_user_ptr()),
                ("oset", Self::syscall_arg_user_ptr()),
                ("sigsetsize", Self::syscall_arg_int(false)),
            ],
            "rt_sigpending" => vec![
                ("uset", Self::syscall_arg_user_ptr()),
                ("sigsetsize", Self::syscall_arg_int(false)),
            ],
            "rt_sigtimedwait" => vec![
                ("uthese", Self::syscall_arg_user_ptr()),
                ("uinfo", Self::syscall_arg_user_ptr()),
                ("uts", Self::syscall_arg_user_ptr()),
                ("sigsetsize", Self::syscall_arg_int(false)),
            ],
            "kill" | "tkill" => vec![
                ("pid", Self::syscall_arg_int(true)),
                ("sig", Self::syscall_arg_int(true)),
            ],
            "tgkill" => vec![
                ("tgid", Self::syscall_arg_int(true)),
                ("pid", Self::syscall_arg_int(true)),
                ("sig", Self::syscall_arg_int(true)),
            ],
            "rt_sigqueueinfo" => vec![
                ("pid", Self::syscall_arg_int(true)),
                ("sig", Self::syscall_arg_int(true)),
                ("uinfo", Self::syscall_arg_user_ptr()),
            ],
            "rt_tgsigqueueinfo" => vec![
                ("tgid", Self::syscall_arg_int(true)),
                ("pid", Self::syscall_arg_int(true)),
                ("sig", Self::syscall_arg_int(true)),
                ("uinfo", Self::syscall_arg_user_ptr()),
            ],
            "sigaltstack" => vec![
                ("uss", Self::syscall_arg_user_ptr()),
                ("uoss", Self::syscall_arg_user_ptr()),
            ],
            "rt_sigaction" => vec![
                ("sig", Self::syscall_arg_int(true)),
                ("act", Self::syscall_arg_user_ptr()),
                ("oact", Self::syscall_arg_user_ptr()),
                ("sigsetsize", Self::syscall_arg_int(false)),
            ],
            "rt_sigsuspend" => vec![
                ("unewset", Self::syscall_arg_user_ptr()),
                ("sigsetsize", Self::syscall_arg_int(false)),
            ],
            "pidfd_send_signal" => vec![
                ("pidfd", Self::syscall_arg_int(true)),
                ("sig", Self::syscall_arg_int(true)),
                ("info", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "pidfd_open" => vec![
                ("pid", Self::syscall_arg_int(true)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "pidfd_getfd" => vec![
                ("pidfd", Self::syscall_arg_int(true)),
                ("fd", Self::syscall_arg_int(true)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "setpriority" => vec![
                ("which", Self::syscall_arg_int(true)),
                ("who", Self::syscall_arg_int(true)),
                ("niceval", Self::syscall_arg_int(true)),
            ],
            "getpriority" => vec![
                ("which", Self::syscall_arg_int(true)),
                ("who", Self::syscall_arg_int(true)),
            ],
            "setregid" => vec![
                ("rgid", Self::syscall_arg_int(false)),
                ("egid", Self::syscall_arg_int(false)),
            ],
            "setgid" => vec![("gid", Self::syscall_arg_int(false))],
            "setreuid" => vec![
                ("ruid", Self::syscall_arg_int(false)),
                ("euid", Self::syscall_arg_int(false)),
            ],
            "setuid" => vec![("uid", Self::syscall_arg_int(false))],
            "setresuid" => vec![
                ("ruid", Self::syscall_arg_int(false)),
                ("euid", Self::syscall_arg_int(false)),
                ("suid", Self::syscall_arg_int(false)),
            ],
            "getresuid" => vec![
                ("ruidp", Self::syscall_arg_user_ptr()),
                ("euidp", Self::syscall_arg_user_ptr()),
                ("suidp", Self::syscall_arg_user_ptr()),
            ],
            "setresgid" => vec![
                ("rgid", Self::syscall_arg_int(false)),
                ("egid", Self::syscall_arg_int(false)),
                ("sgid", Self::syscall_arg_int(false)),
            ],
            "getresgid" => vec![
                ("rgidp", Self::syscall_arg_user_ptr()),
                ("egidp", Self::syscall_arg_user_ptr()),
                ("sgidp", Self::syscall_arg_user_ptr()),
            ],
            "setfsuid" => vec![("uid", Self::syscall_arg_int(false))],
            "setfsgid" => vec![("gid", Self::syscall_arg_int(false))],
            "setpgid" => vec![
                ("pid", Self::syscall_arg_int(true)),
                ("pgid", Self::syscall_arg_int(true)),
            ],
            "getpgid" | "getsid" => vec![("pid", Self::syscall_arg_int(true))],
            "sethostname" | "gethostname" | "setdomainname" => vec![
                ("name", Self::syscall_arg_user_ptr()),
                ("len", Self::syscall_arg_int(true)),
            ],
            "getrlimit" | "setrlimit" => vec![
                ("resource", Self::syscall_arg_int(false)),
                ("rlim", Self::syscall_arg_user_ptr()),
            ],
            "getrusage" => vec![
                ("who", Self::syscall_arg_int(true)),
                ("ru", Self::syscall_arg_user_ptr()),
            ],
            "umask" => vec![("mask", Self::syscall_arg_int(false))],
            "prctl" => vec![
                ("option", Self::syscall_arg_int(true)),
                ("arg2", Self::syscall_arg_int(false)),
                ("arg3", Self::syscall_arg_int(false)),
                ("arg4", Self::syscall_arg_int(false)),
                ("arg5", Self::syscall_arg_int(false)),
            ],
            "getcpu" => vec![
                ("cpup", Self::syscall_arg_user_ptr()),
                ("nodep", Self::syscall_arg_user_ptr()),
                ("unused", Self::syscall_arg_user_ptr()),
            ],
            "getgroups" | "setgroups" => vec![
                ("gidsetsize", Self::syscall_arg_int(true)),
                ("grouplist", Self::syscall_arg_user_ptr()),
            ],
            "capget" => vec![
                ("header", Self::syscall_arg_user_ptr()),
                ("dataptr", Self::syscall_arg_user_ptr()),
            ],
            "capset" => vec![
                ("header", Self::syscall_arg_user_ptr()),
                ("data", Self::syscall_arg_user_ptr()),
            ],
            "nice" => vec![("increment", Self::syscall_arg_int(true))],
            "sched_setscheduler" => vec![
                ("pid", Self::syscall_arg_int(true)),
                ("policy", Self::syscall_arg_int(true)),
                ("param", Self::syscall_arg_user_ptr()),
            ],
            "sched_setparam" => vec![
                ("pid", Self::syscall_arg_int(true)),
                ("param", Self::syscall_arg_user_ptr()),
            ],
            "sched_setattr" => vec![
                ("pid", Self::syscall_arg_int(true)),
                ("uattr", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "sched_getscheduler" => vec![("pid", Self::syscall_arg_int(true))],
            "sched_getparam" => vec![
                ("pid", Self::syscall_arg_int(true)),
                ("param", Self::syscall_arg_user_ptr()),
            ],
            "sched_getattr" => vec![
                ("pid", Self::syscall_arg_int(true)),
                ("uattr", Self::syscall_arg_user_ptr()),
                ("size", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "sched_setaffinity" | "sched_getaffinity" => vec![
                ("pid", Self::syscall_arg_int(true)),
                ("len", Self::syscall_arg_int(false)),
                ("user_mask_ptr", Self::syscall_arg_user_ptr()),
            ],
            "sched_yield" => vec![],
            "sched_get_priority_max" | "sched_get_priority_min" => {
                vec![("policy", Self::syscall_arg_int(true))]
            }
            "sched_rr_get_interval" => vec![
                ("pid", Self::syscall_arg_int(true)),
                ("interval", Self::syscall_arg_user_ptr()),
            ],
            "futex" => vec![
                ("uaddr", Self::syscall_arg_user_ptr()),
                ("op", Self::syscall_arg_int(true)),
                ("val", Self::syscall_arg_int(false)),
                ("utime", Self::syscall_arg_user_ptr()),
                ("uaddr2", Self::syscall_arg_user_ptr()),
                ("val3", Self::syscall_arg_int(false)),
            ],
            "msgget" => vec![
                ("key", Self::syscall_arg_int(true)),
                ("msgflg", Self::syscall_arg_int(true)),
            ],
            "msgctl" => vec![
                ("msqid", Self::syscall_arg_int(true)),
                ("cmd", Self::syscall_arg_int(true)),
                ("buf", Self::syscall_arg_user_ptr()),
            ],
            "msgsnd" => vec![
                ("msqid", Self::syscall_arg_int(true)),
                ("msgp", Self::syscall_arg_user_ptr()),
                ("msgsz", Self::syscall_arg_int(false)),
                ("msgflg", Self::syscall_arg_int(true)),
            ],
            "msgrcv" => vec![
                ("msqid", Self::syscall_arg_int(true)),
                ("msgp", Self::syscall_arg_user_ptr()),
                ("msgsz", Self::syscall_arg_int(false)),
                ("msgtyp", Self::syscall_arg_int(true)),
                ("msgflg", Self::syscall_arg_int(true)),
            ],
            "semget" => vec![
                ("key", Self::syscall_arg_int(true)),
                ("nsems", Self::syscall_arg_int(true)),
                ("semflg", Self::syscall_arg_int(true)),
            ],
            "semctl" => vec![
                ("semid", Self::syscall_arg_int(true)),
                ("semnum", Self::syscall_arg_int(true)),
                ("cmd", Self::syscall_arg_int(true)),
                ("arg", Self::syscall_arg_int(false)),
            ],
            "semtimedop" => vec![
                ("semid", Self::syscall_arg_int(true)),
                ("tsops", Self::syscall_arg_user_ptr()),
                ("nsops", Self::syscall_arg_int(false)),
                ("timeout", Self::syscall_arg_user_ptr()),
            ],
            "semop" => vec![
                ("semid", Self::syscall_arg_int(true)),
                ("tsops", Self::syscall_arg_user_ptr()),
                ("nsops", Self::syscall_arg_int(false)),
            ],
            "shmget" => vec![
                ("key", Self::syscall_arg_int(true)),
                ("size", Self::syscall_arg_int(false)),
                ("shmflg", Self::syscall_arg_int(true)),
            ],
            "shmctl" => vec![
                ("shmid", Self::syscall_arg_int(true)),
                ("cmd", Self::syscall_arg_int(true)),
                ("buf", Self::syscall_arg_user_ptr()),
            ],
            "shmat" => vec![
                ("shmid", Self::syscall_arg_int(true)),
                ("shmaddr", Self::syscall_arg_user_ptr()),
                ("shmflg", Self::syscall_arg_int(true)),
            ],
            "shmdt" => vec![("shmaddr", Self::syscall_arg_user_ptr())],
            _ => return Vec::new(),
        };

        fields
            .iter()
            .enumerate()
            .filter(|(_, (name, _))| Self::sys_enter_arg_field_name_is_reachable(name))
            .filter_map(|(idx, (name, ty))| Self::sys_enter_arg_field(idx, name, ty.clone()))
            .collect()
    }

    /// Create context for sys_exit tracepoints
    ///
    /// Layout: trace_event_raw_sys_exit { trace_entry ent; long id; long ret; }
    pub fn sys_exit(name: &str) -> Self {
        let fields = vec![
            FieldInfo {
                name: "id".into(),
                type_info: TypeInfo::Int {
                    size: 8,
                    signed: true,
                },
                offset: 8,
                size: 8,
                bitfield: None,
            },
            FieldInfo {
                name: "ret".into(),
                type_info: TypeInfo::Int {
                    size: 8,
                    signed: true,
                },
                offset: 16,
                size: 8,
                bitfield: None,
            },
        ];

        let (minimum_kernel, minimum_kernel_source) = Self::syscall_fallback_minimum_kernel(name);

        Self::new_with_source_and_minimum_kernel(
            "syscalls",
            name,
            format!("trace_event_raw_{}", name),
            fields,
            24,
            TracepointContextSource::WellKnownSyscallFallback,
            None,
            minimum_kernel,
            minimum_kernel_source,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sys_enter_fallback_payload_collision_policy_preserves_context_builtins() {
        for name in TRACEPOINT_PRESERVED_FALLBACK_FIELD_NAMES {
            assert!(
                !TracepointContext::sys_enter_arg_field_name_is_reachable(name),
                "{name} should keep resolving to the tracepoint context builtin"
            );
        }

        for name in [
            "arg", "arg0", "arg1", "arg2", "arg3", "arg4", "arg5", "arg99",
        ] {
            assert!(
                !TracepointContext::sys_enter_arg_field_name_is_reachable(name),
                "{name} should keep resolving to generic argument access"
            );
        }

        for name in ["argument", "arg_name", "pidfd", "flags", "oldname"] {
            assert!(
                TracepointContext::sys_enter_arg_field_name_is_reachable(name),
                "{name} should remain available as a syscall payload field"
            );
        }
    }

    #[test]
    fn sys_enter_fallback_hides_collisions_without_repacking_argument_offsets() {
        let pidfd_open = TracepointContext::sys_enter("sys_enter_pidfd_open");
        assert!(!pidfd_open.has_field("pid"));
        assert_eq!(
            pidfd_open
                .get_field("flags")
                .expect("expected pidfd_open flags")
                .offset,
            24
        );

        let prctl = TracepointContext::sys_enter("sys_enter_prctl");
        assert!(prctl.has_field("option"));
        for hidden in ["arg2", "arg3", "arg4", "arg5"] {
            assert!(
                !prctl.has_field(hidden),
                "{hidden} should keep resolving to generic argument access"
            );
        }

        let old_mmap = TracepointContext::sys_enter("sys_enter_old_mmap");
        assert!(old_mmap.has_field("args"));
        assert!(!old_mmap.has_field("arg"));
    }
}
