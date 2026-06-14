const POSIX_TIME_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["timer_create"]
        fields: ["which_clock" "timer_event_spec" "created_timer_id"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["timer_gettime"]
        fields: ["timer_id" "setting"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["timer_getoverrun" "timer_delete"]
        fields: ["timer_id"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["timer_settime"]
        fields: ["timer_id" "flags" "new_setting" "old_setting"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["clock_settime" "clock_gettime" "clock_getres"]
        fields: ["which_clock" "tp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["clock_adjtime"]
        fields: ["which_clock" "utx"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["clock_nanosleep"]
        fields: ["which_clock" "flags" "rqtp" "rmtp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["timerfd_create"]
        fields: ["clockid" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/timerfd.c"
    }
    {
        syscalls: ["timerfd_settime"]
        fields: ["ufd" "flags" "utmr" "otmr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/timerfd.c"
    }
    {
        syscalls: ["timerfd_gettime"]
        fields: ["ufd" "otmr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/timerfd.c"
    }
]
