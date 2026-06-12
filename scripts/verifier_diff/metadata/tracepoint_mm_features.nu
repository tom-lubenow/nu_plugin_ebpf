const MM_TRACEPOINT_FIELD_SPECS = [
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
    {
        syscalls: ["mbind"]
        fields: ["start" "len" "mode" "nmask" "maxnode" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mempolicy.c"
    }
    {
        syscalls: ["set_mempolicy"]
        fields: ["mode" "nmask" "maxnode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mempolicy.c"
    }
    {
        syscalls: ["get_mempolicy"]
        fields: ["policy" "nmask" "maxnode" "addr" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mempolicy.c"
    }
    {
        syscalls: ["migrate_pages"]
        fields: ["maxnode" "old_nodes" "new_nodes"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mempolicy.c"
    }
    {
        syscalls: ["move_pages"]
        fields: ["nr_pages" "pages" "nodes" "status" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/migrate.c"
    }
    {
        syscalls: ["set_mempolicy_home_node"]
        fields: ["start" "len" "home_node" "flags"]
        min_kernel: "5.17"
        source: "https://github.com/torvalds/linux/blob/v5.17/mm/mempolicy.c"
    }
]
