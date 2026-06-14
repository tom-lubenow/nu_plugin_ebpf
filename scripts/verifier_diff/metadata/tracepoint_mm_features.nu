const MM_MISC_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["mlock" "munlock"]
        fields: ["start" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mlock.c"
    }
    {
        syscalls: ["mlock2"]
        fields: ["start" "len" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mlock.c"
    }
    {
        syscalls: ["mlockall"]
        fields: ["flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mlock.c"
    }
    {
        syscalls: ["mincore"]
        fields: ["start" "len" "vec"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mincore.c"
    }
    {
        syscalls: ["msync"]
        fields: ["start" "len" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/msync.c"
    }
    {
        syscalls: ["mseal"]
        fields: ["start" "len" "flags"]
        min_kernel: "6.10"
        source: "https://github.com/torvalds/linux/blob/v6.10/mm/mseal.c"
    }
    {
        syscalls: ["munlockall"]
        fields: []
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mlock.c"
    }
    {
        syscalls: ["swapon"]
        fields: ["specialfile" "swap_flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/swapfile.c"
    }
    {
        syscalls: ["swapoff"]
        fields: ["specialfile"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/swapfile.c"
    }
    {
        syscalls: ["memfd_create"]
        fields: ["uname" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/shmem.c"
    }
    {
        syscalls: ["memfd_secret"]
        fields: ["flags"]
        min_kernel: "5.14"
        source: "https://github.com/torvalds/linux/blob/v5.14/mm/secretmem.c"
    }
]

let MM_TRACEPOINT_FIELD_SPECS = (
    $VIRTUAL_MEMORY_TRACEPOINT_FIELD_SPECS
    | append $MM_MISC_TRACEPOINT_FIELD_SPECS
    | append $MEMPOLICY_TRACEPOINT_FIELD_SPECS
)
