let TIME_TRACEPOINT_FIELD_SPECS = (
    [
    {
        syscalls: ["utime"]
        fields: ["filename" "times"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/utimes.c"
    }
    {
        syscalls: ["utimes"]
        fields: ["filename" "utimes"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/utimes.c"
    }
    {
        syscalls: ["futimesat"]
        fields: ["dfd" "filename" "utimes"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/utimes.c"
    }
    {
        syscalls: ["utimensat"]
        fields: ["dfd" "filename" "utimes" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/utimes.c"
    }
    {
        syscalls: ["time"]
        fields: ["tloc"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/time.c"
    }
    {
        syscalls: ["gettimeofday" "settimeofday"]
        fields: ["tv" "tz"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/time.c"
    }
    {
        syscalls: ["adjtimex"]
        fields: ["txc_p"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/time.c"
    }
    {
        syscalls: ["alarm"]
        fields: ["seconds"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/timer.c"
    }
    {
        syscalls: ["getitimer"]
        fields: ["which" "value"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/itimer.c"
    }
    {
        syscalls: ["setitimer"]
        fields: ["which" "value" "ovalue"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/itimer.c"
    }
    {
        syscalls: ["nanosleep"]
        fields: ["rqtp" "rmtp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/hrtimer.c"
    }
    ]
    | append $POSIX_TIME_TRACEPOINT_FIELD_SPECS
)
