const SYSTEM_RESOURCE_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["getrlimit" "setrlimit"]
        fields: ["resource" "rlim"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getrusage"]
        fields: ["who" "ru"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["prlimit64"]
        fields: ["resource" "new_rlim" "old_rlim"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getcpu"]
        fields: ["cpup" "nodep" "unused"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["times"]
        fields: ["tbuf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["sysinfo"]
        fields: ["info"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
]
