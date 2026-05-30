//! Tracepoint context information from kernel BTF

use super::types::{FieldInfo, TypeInfo};

const SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL: &str = "4.7";
const SYSCALL_TRACEPOINT_FALLBACK_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.7/include/trace/events/syscalls.h";
const READ_WRITE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c";
const OPEN_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/open.c";
const OPENAT2_MIN_KERNEL: &str = "5.6";
const OPENAT2_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.6/fs/open.c";
const EXEC_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/exec.c";
const EXIT_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/exit.c";
const FORK_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/fork.c";
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
            Some("statx") => (Some(STATX_MIN_KERNEL), Some(STATX_SOURCE)),
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
            "statx" => (STATX_MIN_KERNEL, STATX_SOURCE),
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
            "close" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, OPEN_SOURCE),
            "openat" => (
                SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL,
                SYSCALL_TRACEPOINT_FALLBACK_SOURCE,
            ),
            "openat2" => (OPENAT2_MIN_KERNEL, OPENAT2_SOURCE),
            "execve" | "execveat" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, EXEC_SOURCE),
            "exit" | "exit_group" | "waitid" | "wait4" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, EXIT_SOURCE)
            }
            "unshare" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, FORK_SOURCE),
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
            "mkdirat" | "unlinkat" | "symlinkat" | "linkat" | "renameat" | "renameat2" => {
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
            "mlock" | "mlock2" | "munlock" | "mlockall" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MM_MLOCK_SOURCE)
            }
            "mincore" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MM_MINCORE_SOURCE),
            "msync" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MM_MSYNC_SOURCE),
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
            "mkdirat" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("pathname", Self::syscall_arg_user_ptr()),
                ("mode", Self::syscall_arg_int(false)),
            ],
            "unlinkat" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("pathname", Self::syscall_arg_user_ptr()),
                ("flag", Self::syscall_arg_int(true)),
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
            _ => return Vec::new(),
        };

        fields
            .iter()
            .enumerate()
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
