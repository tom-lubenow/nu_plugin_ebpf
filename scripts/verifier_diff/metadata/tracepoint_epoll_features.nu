const EPOLL_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["epoll_create"]
        fields: ["size"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventpoll.c"
    }
    {
        syscalls: ["epoll_create1"]
        fields: ["flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventpoll.c"
    }
    {
        syscalls: ["epoll_ctl"]
        fields: ["epfd" "op" "fd" "event"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventpoll.c"
    }
    {
        syscalls: ["epoll_wait"]
        fields: ["epfd" "events" "maxevents" "timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventpoll.c"
    }
    {
        syscalls: ["epoll_pwait"]
        fields: ["epfd" "events" "maxevents" "timeout" "sigmask" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventpoll.c"
    }
    {
        syscalls: ["epoll_pwait2"]
        fields: ["epfd" "events" "maxevents" "timeout" "sigmask" "sigsetsize"]
        min_kernel: "5.11"
        source: "https://github.com/torvalds/linux/blob/v5.11/fs/eventpoll.c"
    }
]
