const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_FD = {
    key: "tracepoint:syscalls/sys_enter_read:field:fd"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_BUF = {
    key: "tracepoint:syscalls/sys_enter_read:field:buf"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_COUNT = {
    key: "tracepoint:syscalls/sys_enter_read:field:count"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_FD = {
    key: "tracepoint:syscalls/sys_enter_write:field:fd"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_BUF = {
    key: "tracepoint:syscalls/sys_enter_write:field:buf"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_COUNT = {
    key: "tracepoint:syscalls/sys_enter_write:field:count"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_CLOSE_FD = {
    key: "tracepoint:syscalls/sys_enter_close:field:fd"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
}
