const POLL_SELECT_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["poll"]
        fields: ["ufds" "nfds" "timeout_msecs"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/select.c"
    }
    {
        syscalls: ["ppoll"]
        fields: ["ufds" "nfds" "tsp" "sigmask" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/select.c"
    }
    {
        syscalls: ["select"]
        fields: ["n" "inp" "outp" "exp" "tvp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/select.c"
    }
    {
        syscalls: ["pselect6"]
        fields: ["n" "inp" "outp" "exp" "tsp" "sig"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/select.c"
    }
]
