const PROCESS_LIFECYCLE_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["execveat"]
        fields: ["fd" "filename" "argv" "envp" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/exec.c"
    }
    {
        syscalls: ["exit" "exit_group"]
        fields: ["error_code"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/exit.c"
    }
    {
        syscalls: ["waitid"]
        fields: ["which" "upid" "infop" "options" "ru"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/exit.c"
    }
    {
        syscalls: ["wait4"]
        fields: ["upid" "stat_addr" "options" "ru"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/exit.c"
    }
    {
        syscalls: ["unshare"]
        fields: ["unshare_flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/fork.c"
    }
    {
        syscalls: ["clone"]
        fields: ["clone_flags" "newsp" "parent_tidptr" "child_tidptr" "tls"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/fork.c"
    }
    {
        syscalls: ["clone3"]
        fields: ["uargs" "size"]
        min_kernel: "5.3"
        source: "https://github.com/torvalds/linux/blob/v5.3/kernel/fork.c"
    }
    {
        syscalls: ["setns"]
        fields: ["fd" "nstype"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/nsproxy.c"
    }
    {
        syscalls: ["set_tid_address"]
        fields: ["tidptr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/fork.c"
    }
    {
        syscalls: ["kcmp"]
        fields: ["pid1" "pid2" "type" "idx1" "idx2"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/kcmp.c"
    }
]
