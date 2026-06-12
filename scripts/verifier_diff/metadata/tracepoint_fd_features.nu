const FD_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["lseek"]
        fields: ["fd" "offset" "whence"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["fadvise64"]
        fields: ["fd" "offset" "len" "advice"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/fadvise.c"
    }
    {
        syscalls: ["readahead"]
        fields: ["fd" "offset" "count"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/readahead.c"
    }
    {
        syscalls: ["fallocate"]
        fields: ["fd" "mode" "offset" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["syncfs" "fsync" "fdatasync"]
        fields: ["fd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/sync.c"
    }
    {
        syscalls: ["sync_file_range"]
        fields: ["fd" "offset" "nbytes" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/sync.c"
    }
    {
        syscalls: ["fcntl"]
        fields: ["fd" "cmd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/fcntl.c"
    }
    {
        syscalls: ["flock"]
        fields: ["fd" "cmd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/locks.c"
    }
    {
        syscalls: ["ioctl"]
        fields: ["fd" "cmd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/ioctl.c"
    }
    {
        syscalls: ["dup"]
        fields: ["fildes"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/file.c"
    }
    {
        syscalls: ["dup2"]
        fields: ["oldfd" "newfd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/file.c"
    }
    {
        syscalls: ["dup3"]
        fields: ["oldfd" "newfd" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/file.c"
    }
    {
        syscalls: ["pipe"]
        fields: ["fildes"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/pipe.c"
    }
    {
        syscalls: ["pipe2"]
        fields: ["fildes" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/pipe.c"
    }
    {
        syscalls: ["eventfd"]
        fields: ["count"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventfd.c"
    }
    {
        syscalls: ["eventfd2"]
        fields: ["count" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventfd.c"
    }
    {
        syscalls: ["close_range"]
        fields: ["fd" "max_fd" "flags"]
        min_kernel: "5.9"
        source: "https://github.com/torvalds/linux/blob/v5.9/fs/open.c"
    }
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
