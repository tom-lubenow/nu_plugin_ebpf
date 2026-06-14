const PIDFD_SIGNAL_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["pidfd_send_signal"]
        fields: ["pidfd" "sig" "info" "flags"]
        min_kernel: "5.1"
        source: "https://github.com/torvalds/linux/blob/v5.1/kernel/signal.c"
    }
    {
        syscalls: ["pidfd_open"]
        fields: ["flags"]
        min_kernel: "5.3"
        source: "https://github.com/torvalds/linux/blob/v5.3/kernel/pid.c"
    }
    {
        syscalls: ["pidfd_getfd"]
        fields: ["pidfd" "fd" "flags"]
        min_kernel: "5.6"
        source: "https://github.com/torvalds/linux/blob/v5.6/kernel/pid.c"
    }
]
