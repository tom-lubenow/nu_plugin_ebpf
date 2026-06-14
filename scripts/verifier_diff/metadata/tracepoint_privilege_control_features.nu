const PRIVILEGE_CONTROL_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["bpf"]
        fields: ["cmd" "uattr" "size"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/bpf/syscall.c"
    }
    {
        syscalls: ["perf_event_open"]
        fields: ["attr_uptr" "group_fd" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/events/core.c"
    }
    {
        syscalls: ["ptrace"]
        fields: ["request" "addr" "data"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/ptrace.c"
    }
    {
        syscalls: ["seccomp"]
        fields: ["op" "flags" "uargs"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/seccomp.c"
    }
    {
        syscalls: ["userfaultfd"]
        fields: ["flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/userfaultfd.c"
    }
    {
        syscalls: ["getgroups" "setgroups"]
        fields: ["gidsetsize" "grouplist"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/groups.c"
    }
    {
        syscalls: ["capget"]
        fields: ["header" "dataptr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/capability.c"
    }
    {
        syscalls: ["capset"]
        fields: ["header" "data"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/capability.c"
    }
]
