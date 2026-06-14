const NOTIFY_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["inotify_init1"]
        fields: ["flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/notify/inotify/inotify_user.c"
    }
    {
        syscalls: ["inotify_add_watch"]
        fields: ["fd" "pathname" "mask"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/notify/inotify/inotify_user.c"
    }
    {
        syscalls: ["inotify_rm_watch"]
        fields: ["fd" "wd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/notify/inotify/inotify_user.c"
    }
    {
        syscalls: ["fanotify_init"]
        fields: ["flags" "event_f_flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/notify/fanotify/fanotify_user.c"
    }
    {
        syscalls: ["fanotify_mark"]
        fields: ["fanotify_fd" "flags" "mask" "dfd" "pathname"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/notify/fanotify/fanotify_user.c"
    }
]
