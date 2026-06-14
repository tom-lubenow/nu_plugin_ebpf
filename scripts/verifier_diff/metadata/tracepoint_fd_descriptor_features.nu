const FD_DESCRIPTOR_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["dup"]
        fields: ["fildes"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/file.c"
    }
    {
        syscalls: ["dup2"]
        fields: ["oldfd" "newfd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/file.c"
    }
    {
        syscalls: ["dup3"]
        fields: ["oldfd" "newfd" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/file.c"
    }
    {
        syscalls: ["pipe"]
        fields: ["fildes"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/pipe.c"
    }
    {
        syscalls: ["pipe2"]
        fields: ["fildes" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/pipe.c"
    }
    {
        syscalls: ["eventfd"]
        fields: ["count"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventfd.c"
    }
    {
        syscalls: ["eventfd2"]
        fields: ["count" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventfd.c"
    }
    {
        syscalls: ["close_range"]
        fields: ["fd" "max_fd" "flags"]
        min_kernel: "5.9"
        source: "https://github.com/torvalds/linux/blob/v5.9/fs/open.c"
    }
]
