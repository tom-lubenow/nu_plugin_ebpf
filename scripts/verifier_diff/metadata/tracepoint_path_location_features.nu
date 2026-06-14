const PATH_LOCATION_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["chdir" "chroot"]
        fields: ["filename"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchdir"]
        fields: ["fd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["getcwd"]
        fields: ["buf" "size"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/dcache.c"
    }
    {
        syscalls: ["readlink"]
        fields: ["path" "buf" "bufsiz"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/stat.c"
    }
    {
        syscalls: ["readlinkat"]
        fields: ["dfd" "pathname" "buf" "bufsiz"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/stat.c"
    }
    {
        syscalls: ["statfs"]
        fields: ["pathname" "buf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/statfs.c"
    }
    {
        syscalls: ["fstatfs"]
        fields: ["fd" "buf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/statfs.c"
    }
    {
        syscalls: ["getdents" "getdents64"]
        fields: ["fd" "dirent" "count"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/readdir.c"
    }
    {
        syscalls: ["name_to_handle_at"]
        fields: ["dfd" "name" "handle" "mnt_id" "flag"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/fhandle.c"
    }
    {
        syscalls: ["open_by_handle_at"]
        fields: ["mountdirfd" "handle" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/fhandle.c"
    }
]
