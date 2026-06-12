const SOCKET_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["socket"]
        fields: ["family" "type" "protocol"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["socketpair"]
        fields: ["family" "type" "protocol" "usockvec"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["bind"]
        fields: ["fd" "umyaddr" "addrlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["listen"]
        fields: ["fd" "backlog"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["accept"]
        fields: ["fd" "upeer_sockaddr" "upeer_addrlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["connect"]
        fields: ["fd" "uservaddr" "addrlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
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
        syscalls: ["accept4"]
        fields: ["fd" "upeer_sockaddr" "upeer_addrlen" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["setsockopt"]
        fields: ["fd" "level" "optname" "optval" "optlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["getsockopt"]
        fields: ["fd" "level" "optname" "optval" "optlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["getsockname" "getpeername"]
        fields: ["fd" "usockaddr" "usockaddr_len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["shutdown"]
        fields: ["fd" "how"]
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
