//! Tracepoint context information from kernel BTF

use super::types::{FieldInfo, TypeInfo};

const SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL: &str = "4.7";
const SYSCALL_TRACEPOINT_FALLBACK_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.7/include/trace/events/syscalls.h";
const READ_WRITE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c";
const SPLICE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/splice.c";
const OPEN_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/open.c";
const OPENAT2_MIN_KERNEL: &str = "5.6";
const OPENAT2_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.6/fs/open.c";
const FACCESSAT2_MIN_KERNEL: &str = "5.8";
const FACCESSAT2_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.8/fs/open.c";
const FCHMODAT2_MIN_KERNEL: &str = "6.6";
const FCHMODAT2_SOURCE: &str = "https://github.com/torvalds/linux/blob/v6.6/fs/open.c";
const CLOSE_RANGE_MIN_KERNEL: &str = "5.9";
const CLOSE_RANGE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.9/fs/open.c";
const EXEC_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/exec.c";
const EXEC_DOMAIN_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/exec_domain.c";
const EXIT_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/exit.c";
const FORK_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/fork.c";
const CLONE3_MIN_KERNEL: &str = "5.3";
const CLONE3_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.3/kernel/fork.c";
const NSPROXY_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/nsproxy.c";
const MODULE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/module.c";
const KEXEC_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/kexec.c";
const KEXEC_FILE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/kexec_file.c";
const REBOOT_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/reboot.c";
const ACCT_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/acct.c";
const FILE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/file.c";
const FCNTL_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/fcntl.c";
const LOCKS_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/locks.c";
const IOCTL_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/ioctl.c";
const PIPE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/pipe.c";
const EVENTFD_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/eventfd.c";
const EVENTPOLL_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/eventpoll.c";
const EPOLL_PWAIT2_MIN_KERNEL: &str = "5.11";
const EPOLL_PWAIT2_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.11/fs/eventpoll.c";
const INOTIFY_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.7/fs/notify/inotify/inotify_user.c";
const FANOTIFY_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.7/fs/notify/fanotify/fanotify_user.c";
const SELECT_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/select.c";
const SYNC_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/sync.c";
const STAT_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/stat.c";
const STATFS_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/statfs.c";
const FILESYSTEMS_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/filesystems.c";
const READDIR_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/readdir.c";
const FHANDLE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/fhandle.c";
const DCACHE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/dcache.c";
const STATX_MIN_KERNEL: &str = "4.11";
const STATX_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.11/fs/stat.c";
const NAMEI_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c";
const XATTR_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/xattr.c";
const XATTRAT_MIN_KERNEL: &str = "6.13";
const XATTRAT_SOURCE: &str = "https://github.com/torvalds/linux/blob/v6.13/fs/xattr.c";
const MOUNT_API_MIN_KERNEL: &str = "5.2";
const MOUNT_LEGACY_NAMESPACE_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.7/fs/namespace.c";
const MOUNT_API_NAMESPACE_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.2/fs/namespace.c";
const MOUNT_API_FSOPEN_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.2/fs/fsopen.c";
const MOUNT_SETATTR_MIN_KERNEL: &str = "5.12";
const MOUNT_SETATTR_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.12/fs/namespace.c";
const MOUNT_QUERY_MIN_KERNEL: &str = "6.8";
const MOUNT_QUERY_SOURCE: &str = "https://github.com/torvalds/linux/blob/v6.8/fs/namespace.c";
const OPEN_TREE_ATTR_MIN_KERNEL: &str = "6.15";
const OPEN_TREE_ATTR_SOURCE: &str = "https://github.com/torvalds/linux/blob/v6.15/fs/namespace.c";
const QUOTA_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/quota/quota.c";
const QUOTACTL_FD_MIN_KERNEL: &str = "5.14";
const QUOTACTL_FD_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.14/fs/quota/quota.c";
const SOCKET_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/net/socket.c";
const X86_ARCH_PRCTL_MIN_KERNEL: &str = "5.0";
const X86_ARCH_PRCTL_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.0/arch/x86/kernel/process_64.c";
const X86_IOPORT_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/ioport.c";
const X86_LDT_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/ldt.c";
const X86_SIGNAL_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/signal.c";
const X86_SHSTK_MIN_KERNEL: &str = "6.6";
const X86_SHSTK_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.6/arch/x86/kernel/shstk.c";
const X86_URETPROBE_MIN_KERNEL: &str = "6.14";
const X86_URETPROBE_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.14/arch/x86/kernel/uprobes.c";
const X86_MMAP_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/sys_x86_64.c";
const FILE_ATTR_MIN_KERNEL: &str = "6.17";
const FILE_ATTR_SOURCE: &str = "https://github.com/torvalds/linux/blob/v6.17/fs/file_attr.c";
const MM_MMAP_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/mmap.c";
const MM_MPROTECT_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/mprotect.c";
const PKEY_MIN_KERNEL: &str = "4.9";
const PKEY_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.9/mm/mprotect.c";
const MM_MREMAP_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/mremap.c";
const MM_MADVISE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/madvise.c";
const MM_MLOCK_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/mlock.c";
const MM_MINCORE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/mincore.c";
const MM_MSYNC_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/msync.c";
const SWAPFILE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/swapfile.c";
const MEMFD_CREATE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/shmem.c";
const MEMFD_SECRET_MIN_KERNEL: &str = "5.14";
const MEMFD_SECRET_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.14/mm/secretmem.c";
const FADVISE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/fadvise.c";
const READAHEAD_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/readahead.c";
const CACHESTAT_MIN_KERNEL: &str = "6.5";
const CACHESTAT_SOURCE: &str = "https://github.com/torvalds/linux/blob/v6.5/mm/filemap.c";
const MSEAL_MIN_KERNEL: &str = "6.10";
const MSEAL_SOURCE: &str = "https://github.com/torvalds/linux/blob/v6.10/mm/mseal.c";
const PROCESS_MADVISE_MIN_KERNEL: &str = "5.10";
const PROCESS_MADVISE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.10/mm/madvise.c";
const PROCESS_VM_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.7/mm/process_vm_access.c";
const PROCESS_MRELEASE_MIN_KERNEL: &str = "5.15";
const PROCESS_MRELEASE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.15/mm/oom_kill.c";
const MEMPOLICY_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/mempolicy.c";
const MIGRATE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/mm/migrate.c";
const SET_MEMPOLICY_HOME_NODE_MIN_KERNEL: &str = "5.17";
const SET_MEMPOLICY_HOME_NODE_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.17/mm/mempolicy.c";
const UTIMES_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/utimes.c";
const TIME_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/time/time.c";
const TIME_TIMER_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/time/timer.c";
const ITIMER_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/time/itimer.c";
const HRTIMER_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/time/hrtimer.c";
const POSIX_TIMERS_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c";
const TIMERFD_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/timerfd.c";
const IO_URING_MIN_KERNEL: &str = "5.1";
const IO_URING_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.1/fs/io_uring.c";
const AIO_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/aio.c";
const AIO_PGETEVENTS_MIN_KERNEL: &str = "4.18";
const AIO_PGETEVENTS_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.18/fs/aio.c";
const IOPRIO_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/block/ioprio.c";
const KEYCTL_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/security/keys/keyctl.c";
const SIGNAL_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c";
const SIGNALFD_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/signalfd.c";
const RANDOM_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/drivers/char/random.c";
const PIDFD_SEND_SIGNAL_MIN_KERNEL: &str = "5.1";
const PIDFD_SEND_SIGNAL_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.1/kernel/signal.c";
const PIDFD_OPEN_MIN_KERNEL: &str = "5.3";
const PIDFD_OPEN_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.3/kernel/pid.c";
const PIDFD_GETFD_MIN_KERNEL: &str = "5.6";
const PIDFD_GETFD_SOURCE: &str = "https://github.com/torvalds/linux/blob/v5.6/kernel/pid.c";
const LANDLOCK_MIN_KERNEL: &str = "5.13";
const LANDLOCK_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.13/security/landlock/syscalls.c";
const LSM_SYSCALL_MIN_KERNEL: &str = "6.8";
const LSM_SYSCALL_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.8/security/lsm_syscalls.c";
const KERNEL_SYS_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c";
const MEMBARRIER_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/membarrier.c";
const PRINTK_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/printk/printk.c";
const RSEQ_MIN_KERNEL: &str = "4.18";
const RSEQ_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.18/kernel/rseq.c";
const BPF_SYSCALL_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/bpf/syscall.c";
const PERF_EVENT_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/events/core.c";
const KCMP_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/kcmp.c";
const PTRACE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/ptrace.c";
const SECCOMP_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/seccomp.c";
const USERFAULTFD_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/fs/userfaultfd.c";
const GROUPS_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/groups.c";
const CAPABILITY_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/capability.c";
const SCHED_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c";
const FUTEX_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/kernel/futex.c";
const FUTEX_WAITV_MIN_KERNEL: &str = "5.16";
const FUTEX_WAITV_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v5.16/kernel/futex/syscalls.c";
const FUTEX2_MIN_KERNEL: &str = "6.7";
const FUTEX2_SOURCE: &str = "https://github.com/torvalds/linux/blob/v6.7/kernel/futex/syscalls.c";
const POSIX_MQUEUE_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c";
const IPC_MSG_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/ipc/msg.c";
const IPC_SEM_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/ipc/sem.c";
const IPC_SHM_SOURCE: &str = "https://github.com/torvalds/linux/blob/v4.7/ipc/shm.c";
const WELL_KNOWN_SYS_ENTER_SYSCALLS: &[&str] = &[
    "read",
    "write",
    "pread64",
    "pwrite64",
    "readv",
    "writev",
    "preadv",
    "pwritev",
    "preadv2",
    "pwritev2",
    "sendfile",
    "sendfile64",
    "copy_file_range",
    "splice",
    "tee",
    "vmsplice",
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
    "fchmodat2",
    "chown",
    "lchown",
    "fchown",
    "fchownat",
    "chdir",
    "fchdir",
    "chroot",
    "getcwd",
    "readlink",
    "readlinkat",
    "statfs",
    "fstatfs",
    "getdents",
    "getdents64",
    "name_to_handle_at",
    "open_by_handle_at",
    "execve",
    "execveat",
    "exit",
    "exit_group",
    "waitid",
    "wait4",
    "unshare",
    "fork",
    "vfork",
    "clone",
    "clone3",
    "setns",
    "init_module",
    "finit_module",
    "delete_module",
    "kexec_load",
    "kexec_file_load",
    "reboot",
    "acct",
    "lseek",
    "fadvise64",
    "readahead",
    "fallocate",
    "sync",
    "syncfs",
    "fsync",
    "fdatasync",
    "sync_file_range",
    "fcntl",
    "flock",
    "ioctl",
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
    "epoll_pwait2",
    "inotify_init",
    "inotify_init1",
    "inotify_add_watch",
    "inotify_rm_watch",
    "fanotify_init",
    "fanotify_mark",
    "poll",
    "ppoll",
    "select",
    "pselect6",
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
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "getxattr",
    "lgetxattr",
    "fgetxattr",
    "listxattr",
    "llistxattr",
    "flistxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "setxattrat",
    "getxattrat",
    "listxattrat",
    "removexattrat",
    "open_tree",
    "move_mount",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "mount_setattr",
    "statmount",
    "listmount",
    "open_tree_attr",
    "mount",
    "umount",
    "pivot_root",
    "quotactl",
    "quotactl_fd",
    "ustat",
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
    "getsockname",
    "getpeername",
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
    "pkey_mprotect",
    "pkey_alloc",
    "pkey_free",
    "mremap",
    "madvise",
    "process_vm_readv",
    "process_vm_writev",
    "process_madvise",
    "process_mrelease",
    "mbind",
    "set_mempolicy",
    "get_mempolicy",
    "migrate_pages",
    "move_pages",
    "set_mempolicy_home_node",
    "swapon",
    "swapoff",
    "munlockall",
    "mlock",
    "mlock2",
    "munlock",
    "mlockall",
    "mincore",
    "msync",
    "memfd_create",
    "memfd_secret",
    "utime",
    "utimes",
    "futimesat",
    "utimensat",
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
    "io_setup",
    "io_destroy",
    "io_submit",
    "io_cancel",
    "io_getevents",
    "io_pgetevents",
    "ioprio_set",
    "ioprio_get",
    "add_key",
    "request_key",
    "keyctl",
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
    "signalfd",
    "signalfd4",
    "pidfd_send_signal",
    "pidfd_open",
    "pidfd_getfd",
    "landlock_create_ruleset",
    "landlock_add_rule",
    "landlock_restrict_self",
    "lsm_get_self_attr",
    "lsm_set_self_attr",
    "lsm_list_modules",
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
    "prlimit64",
    "personality",
    "umask",
    "prctl",
    "getcpu",
    "getrandom",
    "times",
    "newuname",
    "sysinfo",
    "membarrier",
    "syslog",
    "sysfs",
    "rseq",
    "set_tid_address",
    "bpf",
    "perf_event_open",
    "ptrace",
    "seccomp",
    "userfaultfd",
    "getgroups",
    "setgroups",
    "capget",
    "capset",
    "nice",
    "getpid",
    "gettid",
    "getppid",
    "getuid",
    "geteuid",
    "getgid",
    "getegid",
    "getpgrp",
    "setsid",
    "vhangup",
    "alarm",
    "pause",
    "restart_syscall",
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
    "futex_waitv",
    "futex_wake",
    "futex_wait",
    "futex_requeue",
    "set_robust_list",
    "get_robust_list",
    "mq_open",
    "mq_unlink",
    "mq_timedsend",
    "mq_timedreceive",
    "mq_notify",
    "mq_getsetattr",
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
    "arch_prctl",
    "ioperm",
    "iopl",
    "modify_ldt",
    "rt_sigreturn",
    "map_shadow_stack",
    "uretprobe",
    "kcmp",
    "cachestat",
    "mseal",
    "file_getattr",
    "file_setattr",
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
            Some("fchmodat2") => (Some(FCHMODAT2_MIN_KERNEL), Some(FCHMODAT2_SOURCE)),
            Some("close_range") => (Some(CLOSE_RANGE_MIN_KERNEL), Some(CLOSE_RANGE_SOURCE)),
            Some("epoll_pwait2") => (Some(EPOLL_PWAIT2_MIN_KERNEL), Some(EPOLL_PWAIT2_SOURCE)),
            Some("open_tree" | "move_mount" | "fsmount") => {
                (Some(MOUNT_API_MIN_KERNEL), Some(MOUNT_API_NAMESPACE_SOURCE))
            }
            Some("fsopen" | "fsconfig" | "fspick") => {
                (Some(MOUNT_API_MIN_KERNEL), Some(MOUNT_API_FSOPEN_SOURCE))
            }
            Some("mount_setattr") => (Some(MOUNT_SETATTR_MIN_KERNEL), Some(MOUNT_SETATTR_SOURCE)),
            Some("statmount" | "listmount") => {
                (Some(MOUNT_QUERY_MIN_KERNEL), Some(MOUNT_QUERY_SOURCE))
            }
            Some("open_tree_attr") => {
                (Some(OPEN_TREE_ATTR_MIN_KERNEL), Some(OPEN_TREE_ATTR_SOURCE))
            }
            Some("mount" | "umount" | "pivot_root") => (
                Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
                Some(MOUNT_LEGACY_NAMESPACE_SOURCE),
            ),
            Some("quotactl") => (
                Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
                Some(QUOTA_SOURCE),
            ),
            Some("quotactl_fd") => (Some(QUOTACTL_FD_MIN_KERNEL), Some(QUOTACTL_FD_SOURCE)),
            Some("ustat") => (
                Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
                Some(STATFS_SOURCE),
            ),
            Some("statx") => (Some(STATX_MIN_KERNEL), Some(STATX_SOURCE)),
            Some("fork" | "vfork" | "clone" | "set_tid_address") => (
                Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
                Some(FORK_SOURCE),
            ),
            Some("clone3") => (Some(CLONE3_MIN_KERNEL), Some(CLONE3_SOURCE)),
            Some("personality") => (
                Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
                Some(EXEC_DOMAIN_SOURCE),
            ),
            Some("vhangup") => (
                Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
                Some(OPEN_SOURCE),
            ),
            Some("alarm") => (
                Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
                Some(TIME_TIMER_SOURCE),
            ),
            Some("pause" | "restart_syscall") => (
                Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
                Some(SIGNAL_SOURCE),
            ),
            Some("pkey_mprotect" | "pkey_alloc" | "pkey_free") => {
                (Some(PKEY_MIN_KERNEL), Some(PKEY_SOURCE))
            }
            Some("io_uring_setup" | "io_uring_enter" | "io_uring_register") => {
                (Some(IO_URING_MIN_KERNEL), Some(IO_URING_SOURCE))
            }
            Some("io_pgetevents") => (Some(AIO_PGETEVENTS_MIN_KERNEL), Some(AIO_PGETEVENTS_SOURCE)),
            Some("memfd_secret") => (Some(MEMFD_SECRET_MIN_KERNEL), Some(MEMFD_SECRET_SOURCE)),
            Some("process_madvise") => (
                Some(PROCESS_MADVISE_MIN_KERNEL),
                Some(PROCESS_MADVISE_SOURCE),
            ),
            Some("process_mrelease") => (
                Some(PROCESS_MRELEASE_MIN_KERNEL),
                Some(PROCESS_MRELEASE_SOURCE),
            ),
            Some("set_mempolicy_home_node") => (
                Some(SET_MEMPOLICY_HOME_NODE_MIN_KERNEL),
                Some(SET_MEMPOLICY_HOME_NODE_SOURCE),
            ),
            Some("rseq") => (Some(RSEQ_MIN_KERNEL), Some(RSEQ_SOURCE)),
            Some("syslog") => (
                Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
                Some(PRINTK_SOURCE),
            ),
            Some("sysfs") => (
                Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
                Some(FILESYSTEMS_SOURCE),
            ),
            Some("pidfd_send_signal") => (
                Some(PIDFD_SEND_SIGNAL_MIN_KERNEL),
                Some(PIDFD_SEND_SIGNAL_SOURCE),
            ),
            Some("pidfd_open") => (Some(PIDFD_OPEN_MIN_KERNEL), Some(PIDFD_OPEN_SOURCE)),
            Some("pidfd_getfd") => (Some(PIDFD_GETFD_MIN_KERNEL), Some(PIDFD_GETFD_SOURCE)),
            Some("landlock_create_ruleset" | "landlock_add_rule" | "landlock_restrict_self") => {
                (Some(LANDLOCK_MIN_KERNEL), Some(LANDLOCK_SOURCE))
            }
            Some("lsm_get_self_attr" | "lsm_set_self_attr" | "lsm_list_modules") => {
                (Some(LSM_SYSCALL_MIN_KERNEL), Some(LSM_SYSCALL_SOURCE))
            }
            Some("setxattrat" | "getxattrat" | "listxattrat" | "removexattrat") => {
                (Some(XATTRAT_MIN_KERNEL), Some(XATTRAT_SOURCE))
            }
            Some("futex_waitv") => (Some(FUTEX_WAITV_MIN_KERNEL), Some(FUTEX_WAITV_SOURCE)),
            Some("futex_wake" | "futex_wait" | "futex_requeue") => {
                (Some(FUTEX2_MIN_KERNEL), Some(FUTEX2_SOURCE))
            }
            Some("arch_prctl") => (Some(X86_ARCH_PRCTL_MIN_KERNEL), Some(X86_ARCH_PRCTL_SOURCE)),
            Some("ioperm" | "iopl") => (
                Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
                Some(X86_IOPORT_SOURCE),
            ),
            Some("modify_ldt") => (
                Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
                Some(X86_LDT_SOURCE),
            ),
            Some("rt_sigreturn") => (
                Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
                Some(X86_SIGNAL_SOURCE),
            ),
            Some("map_shadow_stack") => (Some(X86_SHSTK_MIN_KERNEL), Some(X86_SHSTK_SOURCE)),
            Some("uretprobe") => (Some(X86_URETPROBE_MIN_KERNEL), Some(X86_URETPROBE_SOURCE)),
            Some("kcmp") => (
                Some(SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL),
                Some(KCMP_SOURCE),
            ),
            Some("cachestat") => (Some(CACHESTAT_MIN_KERNEL), Some(CACHESTAT_SOURCE)),
            Some("mseal") => (Some(MSEAL_MIN_KERNEL), Some(MSEAL_SOURCE)),
            Some("file_getattr" | "file_setattr") => {
                (Some(FILE_ATTR_MIN_KERNEL), Some(FILE_ATTR_SOURCE))
            }
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
            "fchmodat2" => (FCHMODAT2_MIN_KERNEL, FCHMODAT2_SOURCE),
            "close_range" => (CLOSE_RANGE_MIN_KERNEL, CLOSE_RANGE_SOURCE),
            "epoll_pwait2" => (EPOLL_PWAIT2_MIN_KERNEL, EPOLL_PWAIT2_SOURCE),
            "open_tree" | "move_mount" | "fsmount" => {
                (MOUNT_API_MIN_KERNEL, MOUNT_API_NAMESPACE_SOURCE)
            }
            "fsopen" | "fsconfig" | "fspick" => (MOUNT_API_MIN_KERNEL, MOUNT_API_FSOPEN_SOURCE),
            "mount_setattr" => (MOUNT_SETATTR_MIN_KERNEL, MOUNT_SETATTR_SOURCE),
            "statmount" | "listmount" => (MOUNT_QUERY_MIN_KERNEL, MOUNT_QUERY_SOURCE),
            "open_tree_attr" => (OPEN_TREE_ATTR_MIN_KERNEL, OPEN_TREE_ATTR_SOURCE),
            "mount" | "umount" | "pivot_root" => (
                SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL,
                MOUNT_LEGACY_NAMESPACE_SOURCE,
            ),
            "quotactl" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, QUOTA_SOURCE),
            "quotactl_fd" => (QUOTACTL_FD_MIN_KERNEL, QUOTACTL_FD_SOURCE),
            "ustat" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, STATFS_SOURCE),
            "statx" => (STATX_MIN_KERNEL, STATX_SOURCE),
            "fork" | "vfork" | "clone" | "set_tid_address" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, FORK_SOURCE)
            }
            "clone3" => (CLONE3_MIN_KERNEL, CLONE3_SOURCE),
            "personality" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, EXEC_DOMAIN_SOURCE),
            "vhangup" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, OPEN_SOURCE),
            "alarm" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, TIME_TIMER_SOURCE),
            "pause" | "restart_syscall" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, SIGNAL_SOURCE),
            "pkey_mprotect" | "pkey_alloc" | "pkey_free" => (PKEY_MIN_KERNEL, PKEY_SOURCE),
            "io_uring_setup" | "io_uring_enter" | "io_uring_register" => {
                (IO_URING_MIN_KERNEL, IO_URING_SOURCE)
            }
            "io_pgetevents" => (AIO_PGETEVENTS_MIN_KERNEL, AIO_PGETEVENTS_SOURCE),
            "memfd_secret" => (MEMFD_SECRET_MIN_KERNEL, MEMFD_SECRET_SOURCE),
            "process_madvise" => (PROCESS_MADVISE_MIN_KERNEL, PROCESS_MADVISE_SOURCE),
            "process_mrelease" => (PROCESS_MRELEASE_MIN_KERNEL, PROCESS_MRELEASE_SOURCE),
            "set_mempolicy_home_node" => (
                SET_MEMPOLICY_HOME_NODE_MIN_KERNEL,
                SET_MEMPOLICY_HOME_NODE_SOURCE,
            ),
            "rseq" => (RSEQ_MIN_KERNEL, RSEQ_SOURCE),
            "syslog" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, PRINTK_SOURCE),
            "sysfs" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, FILESYSTEMS_SOURCE),
            "pidfd_send_signal" => (PIDFD_SEND_SIGNAL_MIN_KERNEL, PIDFD_SEND_SIGNAL_SOURCE),
            "pidfd_open" => (PIDFD_OPEN_MIN_KERNEL, PIDFD_OPEN_SOURCE),
            "pidfd_getfd" => (PIDFD_GETFD_MIN_KERNEL, PIDFD_GETFD_SOURCE),
            "landlock_create_ruleset" | "landlock_add_rule" | "landlock_restrict_self" => {
                (LANDLOCK_MIN_KERNEL, LANDLOCK_SOURCE)
            }
            "lsm_get_self_attr" | "lsm_set_self_attr" | "lsm_list_modules" => {
                (LSM_SYSCALL_MIN_KERNEL, LSM_SYSCALL_SOURCE)
            }
            "setxattrat" | "getxattrat" | "listxattrat" | "removexattrat" => {
                (XATTRAT_MIN_KERNEL, XATTRAT_SOURCE)
            }
            "futex_waitv" => (FUTEX_WAITV_MIN_KERNEL, FUTEX_WAITV_SOURCE),
            "futex_wake" | "futex_wait" | "futex_requeue" => (FUTEX2_MIN_KERNEL, FUTEX2_SOURCE),
            "arch_prctl" => (X86_ARCH_PRCTL_MIN_KERNEL, X86_ARCH_PRCTL_SOURCE),
            "ioperm" | "iopl" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, X86_IOPORT_SOURCE),
            "modify_ldt" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, X86_LDT_SOURCE),
            "rt_sigreturn" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, X86_SIGNAL_SOURCE),
            "map_shadow_stack" => (X86_SHSTK_MIN_KERNEL, X86_SHSTK_SOURCE),
            "uretprobe" => (X86_URETPROBE_MIN_KERNEL, X86_URETPROBE_SOURCE),
            "kcmp" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, KCMP_SOURCE),
            "cachestat" => (CACHESTAT_MIN_KERNEL, CACHESTAT_SOURCE),
            "mseal" => (MSEAL_MIN_KERNEL, MSEAL_SOURCE),
            "file_getattr" | "file_setattr" => (FILE_ATTR_MIN_KERNEL, FILE_ATTR_SOURCE),
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
            "read" | "write" | "pread64" | "pwrite64" | "readv" | "writev" | "preadv"
            | "pwritev" | "preadv2" | "pwritev2" | "sendfile" | "sendfile64"
            | "copy_file_range" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, READ_WRITE_SOURCE),
            "splice" | "tee" | "vmsplice" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, SPLICE_SOURCE)
            }
            "close" | "open" | "creat" | "access" | "faccessat" | "truncate" | "truncate64"
            | "ftruncate" | "ftruncate64" | "chmod" | "fchmod" | "fchmodat" | "chown"
            | "lchown" | "fchown" | "fchownat" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, OPEN_SOURCE)
            }
            "chdir" | "fchdir" | "chroot" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, OPEN_SOURCE),
            "getcwd" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, DCACHE_SOURCE),
            "openat" => (
                SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL,
                SYSCALL_TRACEPOINT_FALLBACK_SOURCE,
            ),
            "openat2" => (OPENAT2_MIN_KERNEL, OPENAT2_SOURCE),
            "faccessat2" => (FACCESSAT2_MIN_KERNEL, FACCESSAT2_SOURCE),
            "fchmodat2" => (FCHMODAT2_MIN_KERNEL, FCHMODAT2_SOURCE),
            "close_range" => (CLOSE_RANGE_MIN_KERNEL, CLOSE_RANGE_SOURCE),
            "execve" | "execveat" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, EXEC_SOURCE),
            "exit" | "exit_group" | "waitid" | "wait4" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, EXIT_SOURCE)
            }
            "unshare" | "fork" | "vfork" | "clone" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, FORK_SOURCE)
            }
            "clone3" => (CLONE3_MIN_KERNEL, CLONE3_SOURCE),
            "setns" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, NSPROXY_SOURCE),
            "init_module" | "finit_module" | "delete_module" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MODULE_SOURCE)
            }
            "kexec_load" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, KEXEC_SOURCE),
            "kexec_file_load" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, KEXEC_FILE_SOURCE),
            "reboot" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, REBOOT_SOURCE),
            "acct" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, ACCT_SOURCE),
            "lseek" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, READ_WRITE_SOURCE),
            "fadvise64" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, FADVISE_SOURCE),
            "readahead" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, READAHEAD_SOURCE),
            "fallocate" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, OPEN_SOURCE),
            "sync" | "syncfs" | "fsync" | "fdatasync" | "sync_file_range" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, SYNC_SOURCE)
            }
            "fcntl" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, FCNTL_SOURCE),
            "flock" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, LOCKS_SOURCE),
            "ioctl" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, IOCTL_SOURCE),
            "dup" | "dup2" | "dup3" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, FILE_SOURCE),
            "pipe" | "pipe2" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, PIPE_SOURCE),
            "eventfd" | "eventfd2" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, EVENTFD_SOURCE),
            "epoll_create" | "epoll_create1" | "epoll_ctl" | "epoll_wait" | "epoll_pwait" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, EVENTPOLL_SOURCE)
            }
            "epoll_pwait2" => (EPOLL_PWAIT2_MIN_KERNEL, EPOLL_PWAIT2_SOURCE),
            "inotify_init" | "inotify_init1" | "inotify_add_watch" | "inotify_rm_watch" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, INOTIFY_SOURCE)
            }
            "fanotify_init" | "fanotify_mark" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, FANOTIFY_SOURCE)
            }
            "poll" | "ppoll" | "select" | "pselect6" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, SELECT_SOURCE)
            }
            "stat" | "lstat" | "newstat" | "newlstat" | "stat64" | "lstat64" | "fstat"
            | "newfstat" | "fstat64" | "newfstatat" | "fstatat64" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, STAT_SOURCE)
            }
            "statx" => (STATX_MIN_KERNEL, STATX_SOURCE),
            "readlink" | "readlinkat" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, STAT_SOURCE),
            "statfs" | "fstatfs" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, STATFS_SOURCE),
            "getdents" | "getdents64" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, READDIR_SOURCE),
            "name_to_handle_at" | "open_by_handle_at" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, FHANDLE_SOURCE)
            }
            "mknod" | "mknodat" | "mkdir" | "mkdirat" | "rmdir" | "unlink" | "unlinkat"
            | "symlink" | "symlinkat" | "link" | "linkat" | "rename" | "renameat" | "renameat2" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, NAMEI_SOURCE)
            }
            "setxattr" | "lsetxattr" | "fsetxattr" | "getxattr" | "lgetxattr" | "fgetxattr"
            | "listxattr" | "llistxattr" | "flistxattr" | "removexattr" | "lremovexattr"
            | "fremovexattr" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, XATTR_SOURCE),
            "setxattrat" | "getxattrat" | "listxattrat" | "removexattrat" => {
                (XATTRAT_MIN_KERNEL, XATTRAT_SOURCE)
            }
            "open_tree" | "move_mount" | "fsmount" => {
                (MOUNT_API_MIN_KERNEL, MOUNT_API_NAMESPACE_SOURCE)
            }
            "fsopen" | "fsconfig" | "fspick" => (MOUNT_API_MIN_KERNEL, MOUNT_API_FSOPEN_SOURCE),
            "mount_setattr" => (MOUNT_SETATTR_MIN_KERNEL, MOUNT_SETATTR_SOURCE),
            "statmount" | "listmount" => (MOUNT_QUERY_MIN_KERNEL, MOUNT_QUERY_SOURCE),
            "open_tree_attr" => (OPEN_TREE_ATTR_MIN_KERNEL, OPEN_TREE_ATTR_SOURCE),
            "mount" | "umount" | "pivot_root" => (
                SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL,
                MOUNT_LEGACY_NAMESPACE_SOURCE,
            ),
            "quotactl" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, QUOTA_SOURCE),
            "quotactl_fd" => (QUOTACTL_FD_MIN_KERNEL, QUOTACTL_FD_SOURCE),
            "ustat" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, STATFS_SOURCE),
            "socket" | "socketpair" | "bind" | "listen" | "accept" | "connect" | "sendto"
            | "recvfrom" | "accept4" | "setsockopt" | "getsockopt" | "getsockname"
            | "getpeername" | "shutdown" | "sendmsg" | "recvmsg" | "sendmmsg" | "recvmmsg" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, SOCKET_SOURCE)
            }
            "mmap" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, X86_MMAP_SOURCE),
            "brk" | "mmap_pgoff" | "old_mmap" | "munmap" | "remap_file_pages" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MM_MMAP_SOURCE)
            }
            "mprotect" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MM_MPROTECT_SOURCE),
            "pkey_mprotect" | "pkey_alloc" | "pkey_free" => (PKEY_MIN_KERNEL, PKEY_SOURCE),
            "mremap" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MM_MREMAP_SOURCE),
            "madvise" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MM_MADVISE_SOURCE),
            "process_vm_readv" | "process_vm_writev" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, PROCESS_VM_SOURCE)
            }
            "process_madvise" => (PROCESS_MADVISE_MIN_KERNEL, PROCESS_MADVISE_SOURCE),
            "process_mrelease" => (PROCESS_MRELEASE_MIN_KERNEL, PROCESS_MRELEASE_SOURCE),
            "mlock" | "mlock2" | "munlock" | "mlockall" | "munlockall" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MM_MLOCK_SOURCE)
            }
            "mincore" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MM_MINCORE_SOURCE),
            "msync" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MM_MSYNC_SOURCE),
            "swapon" | "swapoff" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, SWAPFILE_SOURCE),
            "memfd_create" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MEMFD_CREATE_SOURCE),
            "memfd_secret" => (MEMFD_SECRET_MIN_KERNEL, MEMFD_SECRET_SOURCE),
            "mbind" | "set_mempolicy" | "get_mempolicy" | "migrate_pages" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MEMPOLICY_SOURCE)
            }
            "move_pages" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MIGRATE_SOURCE),
            "set_mempolicy_home_node" => (
                SET_MEMPOLICY_HOME_NODE_MIN_KERNEL,
                SET_MEMPOLICY_HOME_NODE_SOURCE,
            ),
            "utime" | "utimes" | "futimesat" | "utimensat" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, UTIMES_SOURCE)
            }
            "time" | "gettimeofday" | "settimeofday" | "adjtimex" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, TIME_SOURCE)
            }
            "alarm" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, TIME_TIMER_SOURCE),
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
            "io_setup" | "io_destroy" | "io_submit" | "io_cancel" | "io_getevents" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, AIO_SOURCE)
            }
            "io_pgetevents" => (AIO_PGETEVENTS_MIN_KERNEL, AIO_PGETEVENTS_SOURCE),
            "ioprio_set" | "ioprio_get" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, IOPRIO_SOURCE),
            "add_key" | "request_key" | "keyctl" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, KEYCTL_SOURCE)
            }
            "rt_sigprocmask" | "rt_sigpending" | "rt_sigtimedwait" | "kill" | "tgkill"
            | "tkill" | "rt_sigqueueinfo" | "rt_tgsigqueueinfo" | "sigaltstack"
            | "rt_sigaction" | "rt_sigsuspend" | "pause" | "restart_syscall" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, SIGNAL_SOURCE)
            }
            "signalfd" | "signalfd4" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, SIGNALFD_SOURCE),
            "pidfd_send_signal" => (PIDFD_SEND_SIGNAL_MIN_KERNEL, PIDFD_SEND_SIGNAL_SOURCE),
            "pidfd_open" => (PIDFD_OPEN_MIN_KERNEL, PIDFD_OPEN_SOURCE),
            "pidfd_getfd" => (PIDFD_GETFD_MIN_KERNEL, PIDFD_GETFD_SOURCE),
            "landlock_create_ruleset" | "landlock_add_rule" | "landlock_restrict_self" => {
                (LANDLOCK_MIN_KERNEL, LANDLOCK_SOURCE)
            }
            "lsm_get_self_attr" | "lsm_set_self_attr" | "lsm_list_modules" => {
                (LSM_SYSCALL_MIN_KERNEL, LSM_SYSCALL_SOURCE)
            }
            "setpriority" | "getpriority" | "setregid" | "setgid" | "setreuid" | "setuid"
            | "setresuid" | "getresuid" | "setresgid" | "getresgid" | "setfsuid" | "setfsgid"
            | "setpgid" | "getpgid" | "getsid" | "setsid" | "getpid" | "gettid" | "getppid"
            | "getuid" | "geteuid" | "getgid" | "getegid" | "getpgrp" | "sethostname"
            | "gethostname" | "setdomainname" | "getrlimit" | "setrlimit" | "getrusage"
            | "prlimit64" | "umask" | "prctl" | "getcpu" | "times" | "newuname" | "sysinfo" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, KERNEL_SYS_SOURCE)
            }
            "personality" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, EXEC_DOMAIN_SOURCE),
            "vhangup" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, OPEN_SOURCE),
            "membarrier" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, MEMBARRIER_SOURCE),
            "syslog" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, PRINTK_SOURCE),
            "sysfs" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, FILESYSTEMS_SOURCE),
            "rseq" => (RSEQ_MIN_KERNEL, RSEQ_SOURCE),
            "set_tid_address" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, FORK_SOURCE),
            "bpf" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, BPF_SYSCALL_SOURCE),
            "perf_event_open" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, PERF_EVENT_SOURCE),
            "ptrace" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, PTRACE_SOURCE),
            "seccomp" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, SECCOMP_SOURCE),
            "userfaultfd" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, USERFAULTFD_SOURCE),
            "getrandom" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, RANDOM_SOURCE),
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
            "futex" | "set_robust_list" | "get_robust_list" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, FUTEX_SOURCE)
            }
            "futex_waitv" => (FUTEX_WAITV_MIN_KERNEL, FUTEX_WAITV_SOURCE),
            "futex_wake" | "futex_wait" | "futex_requeue" => (FUTEX2_MIN_KERNEL, FUTEX2_SOURCE),
            "mq_open" | "mq_unlink" | "mq_timedsend" | "mq_timedreceive" | "mq_notify"
            | "mq_getsetattr" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, POSIX_MQUEUE_SOURCE),
            "msgget" | "msgctl" | "msgsnd" | "msgrcv" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, IPC_MSG_SOURCE)
            }
            "semget" | "semctl" | "semtimedop" | "semop" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, IPC_SEM_SOURCE)
            }
            "shmget" | "shmctl" | "shmat" | "shmdt" => {
                (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, IPC_SHM_SOURCE)
            }
            "arch_prctl" => (X86_ARCH_PRCTL_MIN_KERNEL, X86_ARCH_PRCTL_SOURCE),
            "ioperm" | "iopl" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, X86_IOPORT_SOURCE),
            "modify_ldt" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, X86_LDT_SOURCE),
            "map_shadow_stack" => (X86_SHSTK_MIN_KERNEL, X86_SHSTK_SOURCE),
            "kcmp" => (SYSCALL_TRACEPOINT_FALLBACK_MIN_KERNEL, KCMP_SOURCE),
            "cachestat" => (CACHESTAT_MIN_KERNEL, CACHESTAT_SOURCE),
            "mseal" => (MSEAL_MIN_KERNEL, MSEAL_SOURCE),
            "file_getattr" | "file_setattr" => (FILE_ATTR_MIN_KERNEL, FILE_ATTR_SOURCE),
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
            "pread64" | "pwrite64" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("buf", Self::syscall_arg_user_ptr()),
                ("count", Self::syscall_arg_int(false)),
                ("pos", Self::syscall_arg_int(true)),
            ],
            "readv" | "writev" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("vec", Self::syscall_arg_user_ptr()),
                ("vlen", Self::syscall_arg_int(false)),
            ],
            "preadv" | "pwritev" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("vec", Self::syscall_arg_user_ptr()),
                ("vlen", Self::syscall_arg_int(false)),
                ("pos_l", Self::syscall_arg_int(false)),
                ("pos_h", Self::syscall_arg_int(false)),
            ],
            "preadv2" | "pwritev2" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("vec", Self::syscall_arg_user_ptr()),
                ("vlen", Self::syscall_arg_int(false)),
                ("pos_l", Self::syscall_arg_int(false)),
                ("pos_h", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "sendfile" | "sendfile64" => vec![
                ("out_fd", Self::syscall_arg_int(true)),
                ("in_fd", Self::syscall_arg_int(true)),
                ("offset", Self::syscall_arg_user_ptr()),
                ("count", Self::syscall_arg_int(false)),
            ],
            "copy_file_range" | "splice" => vec![
                ("fd_in", Self::syscall_arg_int(true)),
                ("off_in", Self::syscall_arg_user_ptr()),
                ("fd_out", Self::syscall_arg_int(true)),
                ("off_out", Self::syscall_arg_user_ptr()),
                ("len", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "tee" => vec![
                ("fdin", Self::syscall_arg_int(true)),
                ("fdout", Self::syscall_arg_int(true)),
                ("len", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "vmsplice" => vec![
                ("fd", Self::syscall_arg_int(true)),
                ("iov", Self::syscall_arg_user_ptr()),
                ("nr_segs", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
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
            "fchmodat2" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("mode", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
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
            "chdir" | "chroot" => vec![("filename", Self::syscall_arg_user_ptr())],
            "fchdir" => vec![("fd", Self::syscall_arg_int(false))],
            "getcwd" => vec![
                ("buf", Self::syscall_arg_user_ptr()),
                ("size", Self::syscall_arg_int(false)),
            ],
            "readlink" => vec![
                ("path", Self::syscall_arg_user_ptr()),
                ("buf", Self::syscall_arg_user_ptr()),
                ("bufsiz", Self::syscall_arg_int(true)),
            ],
            "readlinkat" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("pathname", Self::syscall_arg_user_ptr()),
                ("buf", Self::syscall_arg_user_ptr()),
                ("bufsiz", Self::syscall_arg_int(true)),
            ],
            "statfs" => vec![
                ("pathname", Self::syscall_arg_user_ptr()),
                ("buf", Self::syscall_arg_user_ptr()),
            ],
            "fstatfs" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("buf", Self::syscall_arg_user_ptr()),
            ],
            "getdents" | "getdents64" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("dirent", Self::syscall_arg_user_ptr()),
                ("count", Self::syscall_arg_int(false)),
            ],
            "name_to_handle_at" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("name", Self::syscall_arg_user_ptr()),
                ("handle", Self::syscall_arg_user_ptr()),
                ("mnt_id", Self::syscall_arg_user_ptr()),
                ("flag", Self::syscall_arg_int(true)),
            ],
            "open_by_handle_at" => vec![
                ("mountdirfd", Self::syscall_arg_int(true)),
                ("handle", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "file_getattr" | "file_setattr" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("ufattr", Self::syscall_arg_user_ptr()),
                ("usize", Self::syscall_arg_int(false)),
                ("at_flags", Self::syscall_arg_int(false)),
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
            "fork" | "vfork" => vec![],
            "clone" => vec![
                ("clone_flags", Self::syscall_arg_int(false)),
                ("newsp", Self::syscall_arg_int(false)),
                ("parent_tidptr", Self::syscall_arg_user_ptr()),
                ("child_tidptr", Self::syscall_arg_user_ptr()),
                ("tls", Self::syscall_arg_int(false)),
            ],
            "clone3" => vec![
                ("uargs", Self::syscall_arg_user_ptr()),
                ("size", Self::syscall_arg_int(false)),
            ],
            "setns" => vec![
                ("fd", Self::syscall_arg_int(true)),
                ("nstype", Self::syscall_arg_int(true)),
            ],
            "init_module" => vec![
                ("umod", Self::syscall_arg_user_ptr()),
                ("len", Self::syscall_arg_int(false)),
                ("uargs", Self::syscall_arg_user_ptr()),
            ],
            "finit_module" => vec![
                ("fd", Self::syscall_arg_int(true)),
                ("uargs", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "delete_module" => vec![
                ("name_user", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "kexec_load" => vec![
                ("entry", Self::syscall_arg_int(false)),
                ("nr_segments", Self::syscall_arg_int(false)),
                ("segments", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "kexec_file_load" => vec![
                ("kernel_fd", Self::syscall_arg_int(true)),
                ("initrd_fd", Self::syscall_arg_int(true)),
                ("cmdline_len", Self::syscall_arg_int(false)),
                ("cmdline_ptr", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "reboot" => vec![
                ("magic1", Self::syscall_arg_int(true)),
                ("magic2", Self::syscall_arg_int(true)),
                ("cmd", Self::syscall_arg_int(false)),
                ("arg", Self::syscall_arg_user_ptr()),
            ],
            "acct" => vec![("name", Self::syscall_arg_user_ptr())],
            "lseek" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("offset", Self::syscall_arg_int(true)),
                ("whence", Self::syscall_arg_int(false)),
            ],
            "fadvise64" => vec![
                ("fd", Self::syscall_arg_int(true)),
                ("offset", Self::syscall_arg_int(true)),
                ("len", Self::syscall_arg_int(false)),
                ("advice", Self::syscall_arg_int(true)),
            ],
            "readahead" => vec![
                ("fd", Self::syscall_arg_int(true)),
                ("offset", Self::syscall_arg_int(true)),
                ("count", Self::syscall_arg_int(false)),
            ],
            "fallocate" => vec![
                ("fd", Self::syscall_arg_int(true)),
                ("mode", Self::syscall_arg_int(true)),
                ("offset", Self::syscall_arg_int(true)),
                ("len", Self::syscall_arg_int(true)),
            ],
            "sync" => vec![],
            "syncfs" => vec![("fd", Self::syscall_arg_int(true))],
            "fsync" | "fdatasync" => vec![("fd", Self::syscall_arg_int(false))],
            "sync_file_range" => vec![
                ("fd", Self::syscall_arg_int(true)),
                ("offset", Self::syscall_arg_int(true)),
                ("nbytes", Self::syscall_arg_int(true)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "cachestat" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("cstat_range", Self::syscall_arg_user_ptr()),
                ("cstat", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "fcntl" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("cmd", Self::syscall_arg_int(false)),
                ("arg", Self::syscall_arg_int(false)),
            ],
            "flock" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("cmd", Self::syscall_arg_int(false)),
            ],
            "ioctl" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("cmd", Self::syscall_arg_int(false)),
                ("arg", Self::syscall_arg_int(false)),
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
            "epoll_pwait2" => vec![
                ("epfd", Self::syscall_arg_int(true)),
                ("events", Self::syscall_arg_user_ptr()),
                ("maxevents", Self::syscall_arg_int(true)),
                ("timeout", Self::syscall_arg_user_ptr()),
                ("sigmask", Self::syscall_arg_user_ptr()),
                ("sigsetsize", Self::syscall_arg_int(false)),
            ],
            "inotify_init" => vec![],
            "inotify_init1" => vec![("flags", Self::syscall_arg_int(true))],
            "inotify_add_watch" => vec![
                ("fd", Self::syscall_arg_int(true)),
                ("pathname", Self::syscall_arg_user_ptr()),
                ("mask", Self::syscall_arg_int(false)),
            ],
            "inotify_rm_watch" => vec![
                ("fd", Self::syscall_arg_int(true)),
                ("wd", Self::syscall_arg_int(true)),
            ],
            "fanotify_init" => vec![
                ("flags", Self::syscall_arg_int(false)),
                ("event_f_flags", Self::syscall_arg_int(false)),
            ],
            "fanotify_mark" => vec![
                ("fanotify_fd", Self::syscall_arg_int(true)),
                ("flags", Self::syscall_arg_int(false)),
                ("mask", Self::syscall_arg_int(false)),
                ("dfd", Self::syscall_arg_int(true)),
                ("pathname", Self::syscall_arg_user_ptr()),
            ],
            "poll" => vec![
                ("ufds", Self::syscall_arg_user_ptr()),
                ("nfds", Self::syscall_arg_int(false)),
                ("timeout_msecs", Self::syscall_arg_int(true)),
            ],
            "ppoll" => vec![
                ("ufds", Self::syscall_arg_user_ptr()),
                ("nfds", Self::syscall_arg_int(false)),
                ("tsp", Self::syscall_arg_user_ptr()),
                ("sigmask", Self::syscall_arg_user_ptr()),
                ("sigsetsize", Self::syscall_arg_int(false)),
            ],
            "select" => vec![
                ("n", Self::syscall_arg_int(true)),
                ("inp", Self::syscall_arg_user_ptr()),
                ("outp", Self::syscall_arg_user_ptr()),
                ("exp", Self::syscall_arg_user_ptr()),
                ("tvp", Self::syscall_arg_user_ptr()),
            ],
            "pselect6" => vec![
                ("n", Self::syscall_arg_int(true)),
                ("inp", Self::syscall_arg_user_ptr()),
                ("outp", Self::syscall_arg_user_ptr()),
                ("exp", Self::syscall_arg_user_ptr()),
                ("tsp", Self::syscall_arg_user_ptr()),
                ("sig", Self::syscall_arg_user_ptr()),
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
            "setxattr" | "lsetxattr" => vec![
                ("pathname", Self::syscall_arg_user_ptr()),
                ("name", Self::syscall_arg_user_ptr()),
                ("value", Self::syscall_arg_user_ptr()),
                ("size", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "fsetxattr" => vec![
                ("fd", Self::syscall_arg_int(true)),
                ("name", Self::syscall_arg_user_ptr()),
                ("value", Self::syscall_arg_user_ptr()),
                ("size", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "getxattr" | "lgetxattr" => vec![
                ("pathname", Self::syscall_arg_user_ptr()),
                ("name", Self::syscall_arg_user_ptr()),
                ("value", Self::syscall_arg_user_ptr()),
                ("size", Self::syscall_arg_int(false)),
            ],
            "fgetxattr" => vec![
                ("fd", Self::syscall_arg_int(true)),
                ("name", Self::syscall_arg_user_ptr()),
                ("value", Self::syscall_arg_user_ptr()),
                ("size", Self::syscall_arg_int(false)),
            ],
            "listxattr" | "llistxattr" => vec![
                ("pathname", Self::syscall_arg_user_ptr()),
                ("list", Self::syscall_arg_user_ptr()),
                ("size", Self::syscall_arg_int(false)),
            ],
            "flistxattr" => vec![
                ("fd", Self::syscall_arg_int(true)),
                ("list", Self::syscall_arg_user_ptr()),
                ("size", Self::syscall_arg_int(false)),
            ],
            "removexattr" | "lremovexattr" => vec![
                ("pathname", Self::syscall_arg_user_ptr()),
                ("name", Self::syscall_arg_user_ptr()),
            ],
            "fremovexattr" => vec![
                ("fd", Self::syscall_arg_int(true)),
                ("name", Self::syscall_arg_user_ptr()),
            ],
            "setxattrat" | "getxattrat" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("pathname", Self::syscall_arg_user_ptr()),
                ("at_flags", Self::syscall_arg_int(false)),
                ("name", Self::syscall_arg_user_ptr()),
                ("uargs", Self::syscall_arg_user_ptr()),
                ("usize", Self::syscall_arg_int(false)),
            ],
            "listxattrat" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("pathname", Self::syscall_arg_user_ptr()),
                ("at_flags", Self::syscall_arg_int(false)),
                ("list", Self::syscall_arg_user_ptr()),
                ("size", Self::syscall_arg_int(false)),
            ],
            "removexattrat" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("pathname", Self::syscall_arg_user_ptr()),
                ("at_flags", Self::syscall_arg_int(false)),
                ("name", Self::syscall_arg_user_ptr()),
            ],
            "open_tree" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "move_mount" => vec![
                ("from_dfd", Self::syscall_arg_int(true)),
                ("from_pathname", Self::syscall_arg_user_ptr()),
                ("to_dfd", Self::syscall_arg_int(true)),
                ("to_pathname", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "fsopen" => vec![
                ("_fs_name", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "fsconfig" => vec![
                ("fd", Self::syscall_arg_int(true)),
                ("cmd", Self::syscall_arg_int(false)),
                ("_key", Self::syscall_arg_user_ptr()),
                ("_value", Self::syscall_arg_user_ptr()),
                ("aux", Self::syscall_arg_int(true)),
            ],
            "fsmount" => vec![
                ("fs_fd", Self::syscall_arg_int(true)),
                ("flags", Self::syscall_arg_int(false)),
                ("attr_flags", Self::syscall_arg_int(false)),
            ],
            "fspick" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("path", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "mount_setattr" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("path", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
                ("uattr", Self::syscall_arg_user_ptr()),
                ("usize", Self::syscall_arg_int(false)),
            ],
            "statmount" => vec![
                ("req", Self::syscall_arg_user_ptr()),
                ("buf", Self::syscall_arg_user_ptr()),
                ("bufsize", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "listmount" => vec![
                ("req", Self::syscall_arg_user_ptr()),
                ("mnt_ids", Self::syscall_arg_user_ptr()),
                ("nr_mnt_ids", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "open_tree_attr" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
                ("uattr", Self::syscall_arg_user_ptr()),
                ("usize", Self::syscall_arg_int(false)),
            ],
            "mount" => vec![
                ("dev_name", Self::syscall_arg_user_ptr()),
                ("dir_name", Self::syscall_arg_user_ptr()),
                ("type", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
                ("data", Self::syscall_arg_user_ptr()),
            ],
            "umount" => vec![
                ("name", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "pivot_root" => vec![
                ("new_root", Self::syscall_arg_user_ptr()),
                ("put_old", Self::syscall_arg_user_ptr()),
            ],
            "quotactl" => vec![
                ("cmd", Self::syscall_arg_int(false)),
                ("special", Self::syscall_arg_user_ptr()),
                ("id", Self::syscall_arg_int(false)),
                ("addr", Self::syscall_arg_user_ptr()),
            ],
            "quotactl_fd" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("cmd", Self::syscall_arg_int(false)),
                ("id", Self::syscall_arg_int(false)),
                ("addr", Self::syscall_arg_user_ptr()),
            ],
            "ustat" => vec![
                ("dev", Self::syscall_arg_int(false)),
                ("ubuf", Self::syscall_arg_user_ptr()),
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
            "getsockname" | "getpeername" => vec![
                ("fd", Self::syscall_arg_int(false)),
                ("usockaddr", Self::syscall_arg_user_ptr()),
                ("usockaddr_len", Self::syscall_arg_user_ptr()),
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
            "pkey_mprotect" => vec![
                ("start", Self::syscall_arg_int(false)),
                ("len", Self::syscall_arg_int(false)),
                ("prot", Self::syscall_arg_int(false)),
                ("pkey", Self::syscall_arg_int(true)),
            ],
            "pkey_alloc" => vec![
                ("flags", Self::syscall_arg_int(false)),
                ("init_val", Self::syscall_arg_int(false)),
            ],
            "pkey_free" => vec![("pkey", Self::syscall_arg_int(true))],
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
            "process_vm_readv" | "process_vm_writev" => vec![
                ("pid", Self::syscall_arg_int(true)),
                ("lvec", Self::syscall_arg_user_ptr()),
                ("liovcnt", Self::syscall_arg_int(false)),
                ("rvec", Self::syscall_arg_user_ptr()),
                ("riovcnt", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
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
            "mbind" => vec![
                ("start", Self::syscall_arg_int(false)),
                ("len", Self::syscall_arg_int(false)),
                ("mode", Self::syscall_arg_int(false)),
                ("nmask", Self::syscall_arg_user_ptr()),
                ("maxnode", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "set_mempolicy" => vec![
                ("mode", Self::syscall_arg_int(true)),
                ("nmask", Self::syscall_arg_user_ptr()),
                ("maxnode", Self::syscall_arg_int(false)),
            ],
            "get_mempolicy" => vec![
                ("policy", Self::syscall_arg_user_ptr()),
                ("nmask", Self::syscall_arg_user_ptr()),
                ("maxnode", Self::syscall_arg_int(false)),
                ("addr", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "migrate_pages" => vec![
                ("pid", Self::syscall_arg_int(true)),
                ("maxnode", Self::syscall_arg_int(false)),
                ("old_nodes", Self::syscall_arg_user_ptr()),
                ("new_nodes", Self::syscall_arg_user_ptr()),
            ],
            "move_pages" => vec![
                ("pid", Self::syscall_arg_int(true)),
                ("nr_pages", Self::syscall_arg_int(false)),
                ("pages", Self::syscall_arg_user_ptr()),
                ("nodes", Self::syscall_arg_user_ptr()),
                ("status", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "set_mempolicy_home_node" => vec![
                ("start", Self::syscall_arg_int(false)),
                ("len", Self::syscall_arg_int(false)),
                ("home_node", Self::syscall_arg_int(false)),
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
            "munlockall" => vec![],
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
            "mseal" => vec![
                ("start", Self::syscall_arg_int(false)),
                ("len", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "swapon" => vec![
                ("specialfile", Self::syscall_arg_user_ptr()),
                ("swap_flags", Self::syscall_arg_int(true)),
            ],
            "swapoff" => vec![("specialfile", Self::syscall_arg_user_ptr())],
            "memfd_create" => vec![
                ("uname", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "memfd_secret" => vec![("flags", Self::syscall_arg_int(false))],
            "utime" => vec![
                ("filename", Self::syscall_arg_user_ptr()),
                ("times", Self::syscall_arg_user_ptr()),
            ],
            "utimes" => vec![
                ("filename", Self::syscall_arg_user_ptr()),
                ("utimes", Self::syscall_arg_user_ptr()),
            ],
            "futimesat" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("utimes", Self::syscall_arg_user_ptr()),
            ],
            "utimensat" => vec![
                ("dfd", Self::syscall_arg_int(true)),
                ("filename", Self::syscall_arg_user_ptr()),
                ("utimes", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "time" => vec![("tloc", Self::syscall_arg_user_ptr())],
            "gettimeofday" | "settimeofday" => vec![
                ("tv", Self::syscall_arg_user_ptr()),
                ("tz", Self::syscall_arg_user_ptr()),
            ],
            "adjtimex" => vec![("txc_p", Self::syscall_arg_user_ptr())],
            "alarm" => vec![("seconds", Self::syscall_arg_int(false))],
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
            "io_setup" => vec![
                ("nr_events", Self::syscall_arg_int(false)),
                ("ctxp", Self::syscall_arg_user_ptr()),
            ],
            "io_destroy" => vec![("ctx", Self::syscall_arg_int(false))],
            "io_submit" => vec![
                ("ctx_id", Self::syscall_arg_int(false)),
                ("nr", Self::syscall_arg_int(true)),
                ("iocbpp", Self::syscall_arg_user_ptr()),
            ],
            "io_cancel" => vec![
                ("ctx_id", Self::syscall_arg_int(false)),
                ("iocb", Self::syscall_arg_user_ptr()),
                ("result", Self::syscall_arg_user_ptr()),
            ],
            "io_getevents" => vec![
                ("ctx_id", Self::syscall_arg_int(false)),
                ("min_nr", Self::syscall_arg_int(true)),
                ("nr", Self::syscall_arg_int(true)),
                ("events", Self::syscall_arg_user_ptr()),
                ("timeout", Self::syscall_arg_user_ptr()),
            ],
            "io_pgetevents" => vec![
                ("ctx_id", Self::syscall_arg_int(false)),
                ("min_nr", Self::syscall_arg_int(true)),
                ("nr", Self::syscall_arg_int(true)),
                ("events", Self::syscall_arg_user_ptr()),
                ("timeout", Self::syscall_arg_user_ptr()),
                ("usig", Self::syscall_arg_user_ptr()),
            ],
            "ioprio_set" => vec![
                ("which", Self::syscall_arg_int(true)),
                ("who", Self::syscall_arg_int(true)),
                ("ioprio", Self::syscall_arg_int(true)),
            ],
            "ioprio_get" => vec![
                ("which", Self::syscall_arg_int(true)),
                ("who", Self::syscall_arg_int(true)),
            ],
            "add_key" => vec![
                ("_type", Self::syscall_arg_user_ptr()),
                ("_description", Self::syscall_arg_user_ptr()),
                ("_payload", Self::syscall_arg_user_ptr()),
                ("plen", Self::syscall_arg_int(false)),
                ("ringid", Self::syscall_arg_int(true)),
            ],
            "request_key" => vec![
                ("_type", Self::syscall_arg_user_ptr()),
                ("_description", Self::syscall_arg_user_ptr()),
                ("_callout_info", Self::syscall_arg_user_ptr()),
                ("destringid", Self::syscall_arg_int(true)),
            ],
            "keyctl" => vec![
                ("option", Self::syscall_arg_int(true)),
                ("arg2", Self::syscall_arg_int(false)),
                ("arg3", Self::syscall_arg_int(false)),
                ("arg4", Self::syscall_arg_int(false)),
                ("arg5", Self::syscall_arg_int(false)),
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
            "pause" | "restart_syscall" => vec![],
            "signalfd" => vec![
                ("ufd", Self::syscall_arg_int(true)),
                ("user_mask", Self::syscall_arg_user_ptr()),
                ("sizemask", Self::syscall_arg_int(false)),
            ],
            "signalfd4" => vec![
                ("ufd", Self::syscall_arg_int(true)),
                ("user_mask", Self::syscall_arg_user_ptr()),
                ("sizemask", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(true)),
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
            "landlock_create_ruleset" => vec![
                ("attr", Self::syscall_arg_user_ptr()),
                ("size", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "landlock_add_rule" => vec![
                ("ruleset_fd", Self::syscall_arg_int(true)),
                ("rule_type", Self::syscall_arg_int(true)),
                ("rule_attr", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "landlock_restrict_self" => vec![
                ("ruleset_fd", Self::syscall_arg_int(true)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "lsm_get_self_attr" => vec![
                ("attr", Self::syscall_arg_int(false)),
                ("ctx", Self::syscall_arg_user_ptr()),
                ("size", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "lsm_set_self_attr" => vec![
                ("attr", Self::syscall_arg_int(false)),
                ("ctx", Self::syscall_arg_user_ptr()),
                ("size", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "lsm_list_modules" => vec![
                ("ids", Self::syscall_arg_user_ptr()),
                ("size", Self::syscall_arg_user_ptr()),
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
            "prlimit64" => vec![
                ("pid", Self::syscall_arg_int(true)),
                ("resource", Self::syscall_arg_int(false)),
                ("new_rlim", Self::syscall_arg_user_ptr()),
                ("old_rlim", Self::syscall_arg_user_ptr()),
            ],
            "personality" => vec![("personality", Self::syscall_arg_int(false))],
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
            "getrandom" => vec![
                ("buf", Self::syscall_arg_user_ptr()),
                ("count", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "times" => vec![("tbuf", Self::syscall_arg_user_ptr())],
            "newuname" => vec![("name", Self::syscall_arg_user_ptr())],
            "sysinfo" => vec![("info", Self::syscall_arg_user_ptr())],
            "membarrier" => vec![
                ("cmd", Self::syscall_arg_int(true)),
                ("flags", Self::syscall_arg_int(true)),
            ],
            "syslog" => vec![
                ("type", Self::syscall_arg_int(true)),
                ("buf", Self::syscall_arg_user_ptr()),
                ("len", Self::syscall_arg_int(true)),
            ],
            "sysfs" => vec![
                ("option", Self::syscall_arg_int(true)),
                ("arg1", Self::syscall_arg_int(false)),
                ("arg2", Self::syscall_arg_int(false)),
            ],
            "rseq" => vec![
                ("rseq", Self::syscall_arg_user_ptr()),
                ("rseq_len", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(true)),
                ("sig", Self::syscall_arg_int(false)),
            ],
            "set_tid_address" => vec![("tidptr", Self::syscall_arg_user_ptr())],
            "kcmp" => vec![
                ("pid1", Self::syscall_arg_int(true)),
                ("pid2", Self::syscall_arg_int(true)),
                ("type", Self::syscall_arg_int(true)),
                ("idx1", Self::syscall_arg_int(false)),
                ("idx2", Self::syscall_arg_int(false)),
            ],
            "getpid" | "gettid" | "getppid" | "getuid" | "geteuid" | "getgid" | "getegid"
            | "getpgrp" | "setsid" | "vhangup" => vec![],
            "bpf" => vec![
                ("cmd", Self::syscall_arg_int(true)),
                ("uattr", Self::syscall_arg_user_ptr()),
                ("size", Self::syscall_arg_int(false)),
            ],
            "perf_event_open" => vec![
                ("attr_uptr", Self::syscall_arg_user_ptr()),
                ("pid", Self::syscall_arg_int(true)),
                ("cpu", Self::syscall_arg_int(true)),
                ("group_fd", Self::syscall_arg_int(true)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "ptrace" => vec![
                ("request", Self::syscall_arg_int(true)),
                ("pid", Self::syscall_arg_int(true)),
                ("addr", Self::syscall_arg_int(false)),
                ("data", Self::syscall_arg_int(false)),
            ],
            "seccomp" => vec![
                ("op", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
                ("uargs", Self::syscall_arg_user_ptr()),
            ],
            "userfaultfd" => vec![("flags", Self::syscall_arg_int(true))],
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
            "futex_waitv" => vec![
                ("waiters", Self::syscall_arg_user_ptr()),
                ("nr_futexes", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
                ("timeout", Self::syscall_arg_user_ptr()),
                ("clockid", Self::syscall_arg_int(true)),
            ],
            "futex_wake" => vec![
                ("uaddr", Self::syscall_arg_user_ptr()),
                ("mask", Self::syscall_arg_int(false)),
                ("nr", Self::syscall_arg_int(true)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "futex_wait" => vec![
                ("uaddr", Self::syscall_arg_user_ptr()),
                ("val", Self::syscall_arg_int(false)),
                ("mask", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
                ("timeout", Self::syscall_arg_user_ptr()),
                ("clockid", Self::syscall_arg_int(true)),
            ],
            "futex_requeue" => vec![
                ("waiters", Self::syscall_arg_user_ptr()),
                ("flags", Self::syscall_arg_int(false)),
                ("nr_wake", Self::syscall_arg_int(true)),
                ("nr_requeue", Self::syscall_arg_int(true)),
            ],
            "set_robust_list" => vec![
                ("head", Self::syscall_arg_user_ptr()),
                ("len", Self::syscall_arg_int(false)),
            ],
            "get_robust_list" => vec![
                ("pid", Self::syscall_arg_int(true)),
                ("head_ptr", Self::syscall_arg_user_ptr()),
                ("len_ptr", Self::syscall_arg_user_ptr()),
            ],
            "mq_open" => vec![
                ("u_name", Self::syscall_arg_user_ptr()),
                ("oflag", Self::syscall_arg_int(true)),
                ("mode", Self::syscall_arg_int(false)),
                ("u_attr", Self::syscall_arg_user_ptr()),
            ],
            "mq_unlink" => vec![("u_name", Self::syscall_arg_user_ptr())],
            "mq_timedsend" => vec![
                ("mqdes", Self::syscall_arg_int(true)),
                ("u_msg_ptr", Self::syscall_arg_user_ptr()),
                ("msg_len", Self::syscall_arg_int(false)),
                ("msg_prio", Self::syscall_arg_int(false)),
                ("u_abs_timeout", Self::syscall_arg_user_ptr()),
            ],
            "mq_timedreceive" => vec![
                ("mqdes", Self::syscall_arg_int(true)),
                ("u_msg_ptr", Self::syscall_arg_user_ptr()),
                ("msg_len", Self::syscall_arg_int(false)),
                ("u_msg_prio", Self::syscall_arg_user_ptr()),
                ("u_abs_timeout", Self::syscall_arg_user_ptr()),
            ],
            "mq_notify" => vec![
                ("mqdes", Self::syscall_arg_int(true)),
                ("u_notification", Self::syscall_arg_user_ptr()),
            ],
            "mq_getsetattr" => vec![
                ("mqdes", Self::syscall_arg_int(true)),
                ("u_mqstat", Self::syscall_arg_user_ptr()),
                ("u_omqstat", Self::syscall_arg_user_ptr()),
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
            "arch_prctl" => vec![
                ("option", Self::syscall_arg_int(true)),
                ("arg2", Self::syscall_arg_int(false)),
            ],
            "ioperm" => vec![
                ("from", Self::syscall_arg_int(false)),
                ("num", Self::syscall_arg_int(false)),
                ("turn_on", Self::syscall_arg_int(true)),
            ],
            "iopl" => vec![("level", Self::syscall_arg_int(false))],
            "modify_ldt" => vec![
                ("func", Self::syscall_arg_int(true)),
                ("ptr", Self::syscall_arg_user_ptr()),
                ("bytecount", Self::syscall_arg_int(false)),
            ],
            "rt_sigreturn" => vec![],
            "map_shadow_stack" => vec![
                ("addr", Self::syscall_arg_int(false)),
                ("size", Self::syscall_arg_int(false)),
                ("flags", Self::syscall_arg_int(false)),
            ],
            "uretprobe" => vec![],
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
    use std::collections::HashSet;

    #[test]
    fn well_known_sys_enter_syscalls_are_unique() {
        let mut seen = HashSet::new();
        for syscall in TracepointContext::well_known_sys_enter_syscalls() {
            assert!(
                seen.insert(*syscall),
                "duplicate syscall fallback: {syscall}"
            );
        }
    }

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
