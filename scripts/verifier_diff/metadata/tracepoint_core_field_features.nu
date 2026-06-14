const TRACEPOINT_FIELD_KERNEL_FEATURES = [
    { target: "tracepoint:syscalls/sys_enter_read" field: "fd" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_FD }
    { target: "tracepoint:syscalls/sys_enter_read" field: "buf" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_BUF }
    { target: "tracepoint:syscalls/sys_enter_read" field: "count" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_COUNT }
    { target: "tracepoint:syscalls/sys_enter_write" field: "fd" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_FD }
    { target: "tracepoint:syscalls/sys_enter_write" field: "buf" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_BUF }
    { target: "tracepoint:syscalls/sys_enter_write" field: "count" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_COUNT }
    { target: "tracepoint:syscalls/sys_enter_close" field: "fd" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_CLOSE_FD }
    { target: "tracepoint:syscalls/sys_enter_openat" field: "dfd" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_DFD }
    { target: "tracepoint:syscalls/sys_enter_openat" field: "filename" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_FILENAME }
    { target: "tracepoint:syscalls/sys_enter_openat" field: "flags" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_FLAGS }
    { target: "tracepoint:syscalls/sys_enter_openat" field: "mode" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_MODE }
    { target: "tracepoint:syscalls/sys_enter_openat2" field: "dfd" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_DFD }
    { target: "tracepoint:syscalls/sys_enter_openat2" field: "filename" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_FILENAME }
    { target: "tracepoint:syscalls/sys_enter_openat2" field: "how" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_HOW }
    { target: "tracepoint:syscalls/sys_enter_openat2" field: "usize" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_USIZE }
    { target: "tracepoint:syscalls/sys_enter_execve" field: "filename" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_EXECVE_FILENAME }
    { target: "tracepoint:syscalls/sys_enter_execve" field: "argv" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_EXECVE_ARGV }
    { target: "tracepoint:syscalls/sys_enter_execve" field: "envp" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_EXECVE_ENVP }
]
