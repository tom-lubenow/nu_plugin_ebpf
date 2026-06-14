const NAMEI_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["mknod"]
        fields: ["filename" "mode" "dev"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["mknodat"]
        fields: ["dfd" "filename" "mode" "dev"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["mkdir"]
        fields: ["pathname" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["mkdirat"]
        fields: ["dfd" "pathname" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["rmdir" "unlink"]
        fields: ["pathname"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["unlinkat"]
        fields: ["dfd" "pathname" "flag"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["symlink" "link" "rename"]
        fields: ["oldname" "newname"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["symlinkat"]
        fields: ["oldname" "newdfd" "newname"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["linkat"]
        fields: ["olddfd" "oldname" "newdfd" "newname" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["renameat"]
        fields: ["olddfd" "oldname" "newdfd" "newname"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["renameat2"]
        fields: ["olddfd" "oldname" "newdfd" "newname" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
]
