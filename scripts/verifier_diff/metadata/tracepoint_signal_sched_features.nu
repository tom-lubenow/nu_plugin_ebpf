const SIGNAL_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["rt_sigprocmask"]
        fields: ["how" "nset" "oset" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_sigpending"]
        fields: ["uset" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_sigtimedwait"]
        fields: ["uthese" "uinfo" "uts" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["kill" "tkill"]
        fields: ["sig"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["tgkill"]
        fields: ["sig"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_sigqueueinfo"]
        fields: ["sig" "uinfo"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_tgsigqueueinfo"]
        fields: ["sig" "uinfo"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["sigaltstack"]
        fields: ["uss" "uoss"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_sigaction"]
        fields: ["sig" "act" "oact" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_sigsuspend"]
        fields: ["unewset" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["signalfd"]
        fields: ["ufd" "user_mask" "sizemask"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/signalfd.c"
    }
    {
        syscalls: ["signalfd4"]
        fields: ["ufd" "user_mask" "sizemask" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/signalfd.c"
    }
]
