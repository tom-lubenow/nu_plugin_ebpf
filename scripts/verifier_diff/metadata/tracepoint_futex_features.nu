const FUTEX_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["futex"]
        fields: ["uaddr" "op" "val" "utime" "uaddr2" "val3"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/futex.c"
    }
    {
        syscalls: ["futex_waitv"]
        fields: ["waiters" "nr_futexes" "flags" "timeout" "clockid"]
        min_kernel: "5.16"
        source: "https://github.com/torvalds/linux/blob/v5.16/kernel/futex/syscalls.c"
    }
    {
        syscalls: ["futex_wake"]
        fields: ["uaddr" "mask" "nr" "flags"]
        min_kernel: "6.7"
        source: "https://github.com/torvalds/linux/blob/v6.7/kernel/futex/syscalls.c"
    }
    {
        syscalls: ["futex_wait"]
        fields: ["uaddr" "val" "mask" "flags" "timeout" "clockid"]
        min_kernel: "6.7"
        source: "https://github.com/torvalds/linux/blob/v6.7/kernel/futex/syscalls.c"
    }
    {
        syscalls: ["futex_requeue"]
        fields: ["waiters" "flags" "nr_wake" "nr_requeue"]
        min_kernel: "6.7"
        source: "https://github.com/torvalds/linux/blob/v6.7/kernel/futex/syscalls.c"
    }
    {
        syscalls: ["set_robust_list"]
        fields: ["head" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/futex.c"
    }
    {
        syscalls: ["get_robust_list"]
        fields: ["head_ptr" "len_ptr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/futex.c"
    }
]
