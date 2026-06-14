const FILE_DATA_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["pread64" "pwrite64"]
        fields: ["fd" "buf" "count" "pos"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["readv" "writev"]
        fields: ["fd" "vec" "vlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["preadv" "pwritev"]
        fields: ["fd" "vec" "vlen" "pos_l" "pos_h"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["preadv2" "pwritev2"]
        fields: ["fd" "vec" "vlen" "pos_l" "pos_h" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["sendfile" "sendfile64"]
        fields: ["out_fd" "in_fd" "offset" "count"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["copy_file_range"]
        fields: ["fd_in" "off_in" "fd_out" "off_out" "len" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["splice"]
        fields: ["fd_in" "off_in" "fd_out" "off_out" "len" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/splice.c"
    }
    {
        syscalls: ["tee"]
        fields: ["fdin" "fdout" "len" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/splice.c"
    }
    {
        syscalls: ["vmsplice"]
        fields: ["fd" "iov" "nr_segs" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/splice.c"
    }
    {
        syscalls: ["cachestat"]
        fields: ["fd" "cstat_range" "cstat" "flags"]
        min_kernel: "6.5"
        source: "https://github.com/torvalds/linux/blob/v6.5/mm/filemap.c"
    }
]
