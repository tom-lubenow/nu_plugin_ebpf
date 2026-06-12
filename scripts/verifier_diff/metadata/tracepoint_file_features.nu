const FILE_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["open"]
        fields: ["filename" "flags" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["creat"]
        fields: ["pathname" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["access"]
        fields: ["filename" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["faccessat"]
        fields: ["dfd" "filename" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["faccessat2"]
        fields: ["dfd" "filename" "mode" "flags"]
        min_kernel: "5.8"
        source: "https://github.com/torvalds/linux/blob/v5.8/fs/open.c"
    }
    {
        syscalls: ["truncate" "truncate64"]
        fields: ["path" "length"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["ftruncate" "ftruncate64"]
        fields: ["fd" "length"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["chmod"]
        fields: ["filename" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchmod"]
        fields: ["fd" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchmodat"]
        fields: ["dfd" "filename" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchmodat2"]
        fields: ["dfd" "filename" "mode" "flags"]
        min_kernel: "6.6"
        source: "https://github.com/torvalds/linux/blob/v6.6/fs/open.c"
    }
    {
        syscalls: ["chown" "lchown"]
        fields: ["filename" "user" "group"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchown"]
        fields: ["fd" "user" "group"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchownat"]
        fields: ["dfd" "filename" "user" "group" "flag"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
]

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
