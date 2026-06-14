const SOCKET_MESSAGE_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["sendto"]
        fields: ["fd" "buff" "len" "flags" "addr" "addr_len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["recvfrom"]
        fields: ["fd" "ubuf" "size" "flags" "addr" "addr_len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["sendmsg"]
        fields: ["fd" "msg" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["recvmsg"]
        fields: ["fd" "msg" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["sendmmsg"]
        fields: ["fd" "mmsg" "vlen" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["recvmmsg"]
        fields: ["fd" "mmsg" "vlen" "flags" "timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
]
