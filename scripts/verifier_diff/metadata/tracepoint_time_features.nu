const TIME_TRACEPOINT_FIELD_SPECS = [
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
