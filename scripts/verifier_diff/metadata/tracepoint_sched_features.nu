const SCHED_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["nice"]
        fields: ["increment"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_setscheduler"]
        fields: ["policy" "param"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_setparam" "sched_getparam"]
        fields: ["param"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_setattr"]
        fields: ["uattr" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_getattr"]
        fields: ["uattr" "size" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_setaffinity" "sched_getaffinity"]
        fields: ["len" "user_mask_ptr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_get_priority_max" "sched_get_priority_min"]
        fields: ["policy"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_rr_get_interval"]
        fields: ["interval"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
]
