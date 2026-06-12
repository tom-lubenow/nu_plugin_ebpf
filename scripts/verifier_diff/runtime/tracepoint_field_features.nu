let SOURCE_BACKED_SYSCALL_TRACEPOINT_FIELD_SPECS = (
    $FILE_TRACEPOINT_FIELD_SPECS
    | append $FILE_DATA_TRACEPOINT_FIELD_SPECS
    | append $SOCKET_TRACEPOINT_FIELD_SPECS
    | append $PATH_TRACEPOINT_FIELD_SPECS
    | append $QUOTA_TRACEPOINT_FIELD_SPECS
    | append $PROCESS_TRACEPOINT_FIELD_SPECS
    | append $FD_TRACEPOINT_FIELD_SPECS
    | append $MM_TRACEPOINT_FIELD_SPECS
    | append $TIME_TRACEPOINT_FIELD_SPECS
    | append $IO_URING_TRACEPOINT_FIELD_SPECS
    | append $AIO_TRACEPOINT_FIELD_SPECS
    | append $IOPRIO_TRACEPOINT_FIELD_SPECS
    | append $KEY_TRACEPOINT_FIELD_SPECS
    | append $SIGNAL_TRACEPOINT_FIELD_SPECS
    | append $LANDLOCK_TRACEPOINT_FIELD_SPECS
    | append $LSM_SYSCALL_TRACEPOINT_FIELD_SPECS
    | append $IDENTITY_TRACEPOINT_FIELD_SPECS
    | append $SCHED_TRACEPOINT_FIELD_SPECS
    | append $FUTEX_TRACEPOINT_FIELD_SPECS
    | append $MQUEUE_TRACEPOINT_FIELD_SPECS
    | append $IPC_TRACEPOINT_FIELD_SPECS
    | append $X86_TRACEPOINT_FIELD_SPECS
)

def syscall-tracepoint-fallback-field-kernel-feature [field: string target] {
    let target_text = ($target | default "")
    if not ($target_text | str starts-with "tracepoint:syscalls/") {
        return null
    }

    let name = ($target_text | str replace "tracepoint:syscalls/" "")
    let syscall = if ($name | str starts-with "sys_enter_") {
        if $field not-in ["id" "args"] {
            return null
        }
        $name | str replace "sys_enter_" ""
    } else if ($name | str starts-with "sys_exit_") {
        if $field not-in ["id" "ret"] {
            return null
        }
        $name | str replace "sys_exit_" ""
    } else {
        return null
    }

    let min_kernel = if $syscall == "openat2" {
        "5.6"
    } else if $syscall == "faccessat2" {
        "5.8"
    } else if $syscall == "fchmodat2" {
        "6.6"
    } else if $syscall == "close_range" {
        "5.9"
    } else if $syscall == "epoll_pwait2" {
        "5.11"
    } else if $syscall in ["open_tree" "move_mount" "fsmount" "fsopen" "fsconfig" "fspick"] {
        "5.2"
    } else if $syscall == "mount_setattr" {
        "5.12"
    } else if $syscall in ["statmount" "listmount"] {
        "6.8"
    } else if $syscall == "open_tree_attr" {
        "6.15"
    } else if $syscall == "quotactl_fd" {
        "5.14"
    } else if $syscall == "pidfd_send_signal" {
        "5.1"
    } else if $syscall == "pidfd_open" {
        "5.3"
    } else if $syscall == "pidfd_getfd" {
        "5.6"
    } else if $syscall in ["landlock_create_ruleset" "landlock_add_rule" "landlock_restrict_self"] {
        "5.13"
    } else if $syscall in ["lsm_get_self_attr" "lsm_set_self_attr" "lsm_list_modules"] {
        "6.8"
    } else if $syscall in ["setxattrat" "getxattrat" "listxattrat" "removexattrat"] {
        "6.13"
    } else if $syscall == "futex_waitv" {
        "5.16"
    } else if $syscall in ["futex_wake" "futex_wait" "futex_requeue"] {
        "6.7"
    } else if $syscall == "arch_prctl" {
        "5.0"
    } else if $syscall == "map_shadow_stack" {
        "6.6"
    } else if $syscall == "uretprobe" {
        "6.14"
    } else if $syscall == "cachestat" {
        "6.5"
    } else if $syscall == "mseal" {
        "6.10"
    } else if $syscall in ["file_getattr" "file_setattr"] {
        "6.17"
    } else if $syscall == "clone3" {
        "5.3"
    } else if $syscall in ["pkey_mprotect" "pkey_alloc" "pkey_free"] {
        "4.9"
    } else if $syscall in ["io_uring_setup" "io_uring_enter" "io_uring_register"] {
        "5.1"
    } else if $syscall == "io_pgetevents" {
        "4.18"
    } else if $syscall == "memfd_secret" {
        "5.14"
    } else if $syscall == "process_madvise" {
        "5.10"
    } else if $syscall == "process_mrelease" {
        "5.15"
    } else if $syscall == "set_mempolicy_home_node" {
        "5.17"
    } else if $syscall == "rseq" {
        "4.18"
    } else if $syscall == "statx" {
        "4.11"
    } else {
        "4.7"
    }
    let source = if $syscall == "openat2" {
        "https://github.com/torvalds/linux/blob/v5.6/fs/open.c"
    } else if $syscall == "faccessat2" {
        "https://github.com/torvalds/linux/blob/v5.8/fs/open.c"
    } else if $syscall == "fchmodat2" {
        "https://github.com/torvalds/linux/blob/v6.6/fs/open.c"
    } else if $syscall == "close_range" {
        "https://github.com/torvalds/linux/blob/v5.9/fs/open.c"
    } else if $syscall == "epoll_pwait2" {
        "https://github.com/torvalds/linux/blob/v5.11/fs/eventpoll.c"
    } else if $syscall in ["open_tree" "move_mount" "fsmount"] {
        "https://github.com/torvalds/linux/blob/v5.2/fs/namespace.c"
    } else if $syscall in ["fsopen" "fsconfig" "fspick"] {
        "https://github.com/torvalds/linux/blob/v5.2/fs/fsopen.c"
    } else if $syscall == "mount_setattr" {
        "https://github.com/torvalds/linux/blob/v5.12/fs/namespace.c"
    } else if $syscall in ["statmount" "listmount"] {
        "https://github.com/torvalds/linux/blob/v6.8/fs/namespace.c"
    } else if $syscall == "open_tree_attr" {
        "https://github.com/torvalds/linux/blob/v6.15/fs/namespace.c"
    } else if $syscall in ["mount" "umount" "pivot_root"] {
        "https://github.com/torvalds/linux/blob/v4.7/fs/namespace.c"
    } else if $syscall == "quotactl" {
        "https://github.com/torvalds/linux/blob/v4.7/fs/quota/quota.c"
    } else if $syscall == "quotactl_fd" {
        "https://github.com/torvalds/linux/blob/v5.14/fs/quota/quota.c"
    } else if $syscall == "ustat" {
        "https://github.com/torvalds/linux/blob/v4.7/fs/statfs.c"
    } else if $syscall == "pidfd_send_signal" {
        "https://github.com/torvalds/linux/blob/v5.1/kernel/signal.c"
    } else if $syscall == "pidfd_open" {
        "https://github.com/torvalds/linux/blob/v5.3/kernel/pid.c"
    } else if $syscall == "pidfd_getfd" {
        "https://github.com/torvalds/linux/blob/v5.6/kernel/pid.c"
    } else if $syscall in ["landlock_create_ruleset" "landlock_add_rule" "landlock_restrict_self"] {
        "https://github.com/torvalds/linux/blob/v5.13/security/landlock/syscalls.c"
    } else if $syscall in ["lsm_get_self_attr" "lsm_set_self_attr" "lsm_list_modules"] {
        "https://github.com/torvalds/linux/blob/v6.8/security/lsm_syscalls.c"
    } else if $syscall in ["setxattrat" "getxattrat" "listxattrat" "removexattrat"] {
        "https://github.com/torvalds/linux/blob/v6.13/fs/xattr.c"
    } else if $syscall == "futex_waitv" {
        "https://github.com/torvalds/linux/blob/v5.16/kernel/futex/syscalls.c"
    } else if $syscall in ["futex_wake" "futex_wait" "futex_requeue"] {
        "https://github.com/torvalds/linux/blob/v6.7/kernel/futex/syscalls.c"
    } else if $syscall == "arch_prctl" {
        "https://github.com/torvalds/linux/blob/v5.0/arch/x86/kernel/process_64.c"
    } else if $syscall in ["ioperm" "iopl"] {
        "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/ioport.c"
    } else if $syscall == "modify_ldt" {
        "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/ldt.c"
    } else if $syscall == "rt_sigreturn" {
        "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/signal.c"
    } else if $syscall == "map_shadow_stack" {
        "https://github.com/torvalds/linux/blob/v6.6/arch/x86/kernel/shstk.c"
    } else if $syscall == "uretprobe" {
        "https://github.com/torvalds/linux/blob/v6.14/arch/x86/kernel/uprobes.c"
    } else if $syscall == "kcmp" {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/kcmp.c"
    } else if $syscall == "cachestat" {
        "https://github.com/torvalds/linux/blob/v6.5/mm/filemap.c"
    } else if $syscall == "mseal" {
        "https://github.com/torvalds/linux/blob/v6.10/mm/mseal.c"
    } else if $syscall in ["file_getattr" "file_setattr"] {
        "https://github.com/torvalds/linux/blob/v6.17/fs/file_attr.c"
    } else if $syscall == "clone3" {
        "https://github.com/torvalds/linux/blob/v5.3/kernel/fork.c"
    } else if $syscall in ["fork" "vfork" "clone" "set_tid_address"] {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/fork.c"
    } else if $syscall == "personality" {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/exec_domain.c"
    } else if $syscall == "vhangup" {
        "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    } else if $syscall == "alarm" {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/time/timer.c"
    } else if $syscall in ["pause" "restart_syscall"] {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    } else if $syscall == "syslog" {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/printk/printk.c"
    } else if $syscall == "sysfs" {
        "https://github.com/torvalds/linux/blob/v4.7/fs/filesystems.c"
    } else if $syscall in ["pkey_mprotect" "pkey_alloc" "pkey_free"] {
        "https://github.com/torvalds/linux/blob/v4.9/mm/mprotect.c"
    } else if $syscall in ["io_uring_setup" "io_uring_enter" "io_uring_register"] {
        "https://github.com/torvalds/linux/blob/v5.1/fs/io_uring.c"
    } else if $syscall == "io_pgetevents" {
        "https://github.com/torvalds/linux/blob/v4.18/fs/aio.c"
    } else if $syscall == "memfd_secret" {
        "https://github.com/torvalds/linux/blob/v5.14/mm/secretmem.c"
    } else if $syscall == "process_madvise" {
        "https://github.com/torvalds/linux/blob/v5.10/mm/madvise.c"
    } else if $syscall == "process_mrelease" {
        "https://github.com/torvalds/linux/blob/v5.15/mm/oom_kill.c"
    } else if $syscall == "set_mempolicy_home_node" {
        "https://github.com/torvalds/linux/blob/v5.17/mm/mempolicy.c"
    } else if $syscall == "rseq" {
        "https://github.com/torvalds/linux/blob/v4.18/kernel/rseq.c"
    } else if $syscall == "statx" {
        "https://github.com/torvalds/linux/blob/v4.11/fs/stat.c"
    } else {
        "https://github.com/torvalds/linux/blob/v4.7/include/trace/events/syscalls.h"
    }

    {
        key: $"tracepoint:syscalls/($name):field:($field)"
        min_kernel: $min_kernel
        source: $source
    }
}

def source-backed-sys-enter-tracepoint-field-kernel-feature [field: string target specs] {
    let target_text = ($target | default "")
    if not ($target_text | str starts-with "tracepoint:syscalls/sys_enter_") {
        return null
    }

    let syscall = ($target_text | str replace "tracepoint:syscalls/sys_enter_" "")
    let matches = (
        $specs
        | where {|entry| $syscall in $entry.syscalls and $field in $entry.fields }
    )
    if ($matches | is-empty) {
        return null
    }

    let spec = ($matches | first)
    {
        key: $"tracepoint:syscalls/sys_enter_($syscall):field:($field)"
        min_kernel: $spec.min_kernel
        source: $spec.source
    }
}

def tracepoint-payload-field-kernel-feature [field: string target] {
    let target_text = ($target | default "")
    if not ($target_text | str starts-with "tracepoint:") {
        return null
    }
    if (tracepoint-built-in-context-field? $field) {
        return null
    }

    let fallback = (syscall-tracepoint-fallback-field-kernel-feature $field $target)
    if $fallback != null {
        return $fallback
    }

    let source_backed_feature = (
        source-backed-sys-enter-tracepoint-field-kernel-feature $field $target $SOURCE_BACKED_SYSCALL_TRACEPOINT_FIELD_SPECS
    )
    if $source_backed_feature != null {
        return $source_backed_feature
    }

    let matches = (
        $TRACEPOINT_FIELD_KERNEL_FEATURES
        | where {|entry| $entry.target == $target_text and $entry.field == $field }
    )
    if ($matches | is-empty) {
        null
    } else {
        $matches | first | get feature
    }
}
