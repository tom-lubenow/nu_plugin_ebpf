const IDENTITY_CORE_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["setpriority"]
        fields: ["which" "who" "niceval"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getpriority"]
        fields: ["which" "who"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["setregid"]
        fields: ["rgid" "egid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["setreuid"]
        fields: ["ruid" "euid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["setresuid"]
        fields: ["ruid" "euid" "suid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getresuid"]
        fields: ["ruidp" "euidp" "suidp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["setresgid"]
        fields: ["rgid" "egid" "sgid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getresgid"]
        fields: ["rgidp" "egidp" "sgidp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["setpgid"]
        fields: ["pgid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
]

let IDENTITY_TRACEPOINT_FIELD_SPECS = (
    $IDENTITY_CORE_TRACEPOINT_FIELD_SPECS
    | append $SYSTEM_CONTROL_TRACEPOINT_FIELD_SPECS
    | append $PRIVILEGE_CONTROL_TRACEPOINT_FIELD_SPECS
)
