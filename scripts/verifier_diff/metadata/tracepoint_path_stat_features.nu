const PATH_STAT_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["stat" "lstat" "newstat" "newlstat" "stat64" "lstat64"]
        fields: ["filename" "statbuf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/stat.c"
    }
    {
        syscalls: ["fstat" "newfstat" "fstat64"]
        fields: ["fd" "statbuf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/stat.c"
    }
    {
        syscalls: ["newfstatat" "fstatat64"]
        fields: ["dfd" "filename" "statbuf" "flag"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/stat.c"
    }
    {
        syscalls: ["statx"]
        fields: ["dfd" "filename" "flags" "mask" "buffer"]
        min_kernel: "4.11"
        source: "https://github.com/torvalds/linux/blob/v4.11/fs/stat.c"
    }
    {
        syscalls: ["file_getattr" "file_setattr"]
        fields: ["dfd" "filename" "ufattr" "usize" "at_flags"]
        min_kernel: "6.17"
        source: "https://github.com/torvalds/linux/blob/v6.17/fs/file_attr.c"
    }
]
