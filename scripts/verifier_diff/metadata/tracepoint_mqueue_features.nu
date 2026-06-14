const MQUEUE_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["mq_open"]
        fields: ["u_name" "oflag" "mode" "u_attr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
    {
        syscalls: ["mq_unlink"]
        fields: ["u_name"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
    {
        syscalls: ["mq_timedsend"]
        fields: ["mqdes" "u_msg_ptr" "msg_len" "msg_prio" "u_abs_timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
    {
        syscalls: ["mq_timedreceive"]
        fields: ["mqdes" "u_msg_ptr" "msg_len" "u_msg_prio" "u_abs_timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
    {
        syscalls: ["mq_notify"]
        fields: ["mqdes" "u_notification"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
    {
        syscalls: ["mq_getsetattr"]
        fields: ["mqdes" "u_mqstat" "u_omqstat"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
]
