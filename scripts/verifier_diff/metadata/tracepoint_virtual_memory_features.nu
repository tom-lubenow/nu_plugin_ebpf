const VIRTUAL_MEMORY_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["brk"]
        fields: ["brk"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mmap.c"
    }
    {
        syscalls: ["mmap"]
        fields: ["addr" "len" "prot" "flags" "fd" "off"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/sys_x86_64.c"
    }
    {
        syscalls: ["mmap_pgoff"]
        fields: ["addr" "len" "prot" "flags" "fd" "pgoff"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mmap.c"
    }
    {
        syscalls: ["munmap"]
        fields: ["addr" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mmap.c"
    }
    {
        syscalls: ["remap_file_pages"]
        fields: ["start" "size" "prot" "pgoff" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mmap.c"
    }
    {
        syscalls: ["mprotect"]
        fields: ["start" "len" "prot"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mprotect.c"
    }
    {
        syscalls: ["pkey_mprotect"]
        fields: ["start" "len" "prot" "pkey"]
        min_kernel: "4.9"
        source: "https://github.com/torvalds/linux/blob/v4.9/mm/mprotect.c"
    }
    {
        syscalls: ["pkey_alloc"]
        fields: ["flags" "init_val"]
        min_kernel: "4.9"
        source: "https://github.com/torvalds/linux/blob/v4.9/mm/mprotect.c"
    }
    {
        syscalls: ["pkey_free"]
        fields: ["pkey"]
        min_kernel: "4.9"
        source: "https://github.com/torvalds/linux/blob/v4.9/mm/mprotect.c"
    }
    {
        syscalls: ["mremap"]
        fields: ["addr" "old_len" "new_len" "flags" "new_addr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mremap.c"
    }
    {
        syscalls: ["madvise"]
        fields: ["start" "len_in" "behavior"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/madvise.c"
    }
    {
        syscalls: ["process_vm_readv" "process_vm_writev"]
        fields: ["lvec" "liovcnt" "rvec" "riovcnt" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/process_vm_access.c"
    }
    {
        syscalls: ["process_madvise"]
        fields: ["pidfd" "vec" "vlen" "behavior" "flags"]
        min_kernel: "5.10"
        source: "https://github.com/torvalds/linux/blob/v5.10/mm/madvise.c"
    }
    {
        syscalls: ["process_mrelease"]
        fields: ["pidfd" "flags"]
        min_kernel: "5.15"
        source: "https://github.com/torvalds/linux/blob/v5.15/mm/oom_kill.c"
    }
]
