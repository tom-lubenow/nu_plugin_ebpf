const FD_FILE_OP_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["lseek"]
        fields: ["fd" "offset" "whence"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["fadvise64"]
        fields: ["fd" "offset" "len" "advice"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/fadvise.c"
    }
    {
        syscalls: ["readahead"]
        fields: ["fd" "offset" "count"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/readahead.c"
    }
    {
        syscalls: ["fallocate"]
        fields: ["fd" "mode" "offset" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["syncfs" "fsync" "fdatasync"]
        fields: ["fd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/sync.c"
    }
    {
        syscalls: ["sync_file_range"]
        fields: ["fd" "offset" "nbytes" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/sync.c"
    }
    {
        syscalls: ["fcntl"]
        fields: ["fd" "cmd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/fcntl.c"
    }
    {
        syscalls: ["flock"]
        fields: ["fd" "cmd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/locks.c"
    }
    {
        syscalls: ["ioctl"]
        fields: ["fd" "cmd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/ioctl.c"
    }
]
