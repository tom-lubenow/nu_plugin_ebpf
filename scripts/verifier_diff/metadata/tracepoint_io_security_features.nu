const IO_URING_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["io_uring_setup"]
        fields: ["entries" "params"]
        min_kernel: "5.1"
        source: "https://github.com/torvalds/linux/blob/v5.1/fs/io_uring.c"
    }
    {
        syscalls: ["io_uring_enter"]
        fields: ["fd" "to_submit" "min_complete" "flags" "sig" "sigsz"]
        min_kernel: "5.1"
        source: "https://github.com/torvalds/linux/blob/v5.1/fs/io_uring.c"
    }
    {
        syscalls: ["io_uring_register"]
        fields: ["fd" "opcode" "nr_args"]
        min_kernel: "5.1"
        source: "https://github.com/torvalds/linux/blob/v5.1/fs/io_uring.c"
    }
]

const AIO_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["io_setup"]
        fields: ["nr_events" "ctxp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/aio.c"
    }
    {
        syscalls: ["io_destroy"]
        fields: ["ctx"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/aio.c"
    }
    {
        syscalls: ["io_submit"]
        fields: ["ctx_id" "nr" "iocbpp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/aio.c"
    }
    {
        syscalls: ["io_cancel"]
        fields: ["ctx_id" "iocb" "result"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/aio.c"
    }
    {
        syscalls: ["io_getevents"]
        fields: ["ctx_id" "min_nr" "nr" "events" "timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/aio.c"
    }
    {
        syscalls: ["io_pgetevents"]
        fields: ["ctx_id" "min_nr" "nr" "events" "timeout" "usig"]
        min_kernel: "4.18"
        source: "https://github.com/torvalds/linux/blob/v4.18/fs/aio.c"
    }
]

const IOPRIO_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["ioprio_set"]
        fields: ["which" "who" "ioprio"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/block/ioprio.c"
    }
    {
        syscalls: ["ioprio_get"]
        fields: ["which" "who"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/block/ioprio.c"
    }
]
