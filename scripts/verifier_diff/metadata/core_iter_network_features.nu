const KERNEL_FEATURE_ITER_TARGET_TCP = {
    key: "iter-target:tcp"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/net/ipv4/tcp_ipv4.c"
}
const KERNEL_FEATURE_ITER_TARGET_UDP = {
    key: "iter-target:udp"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/net/ipv4/udp.c"
}
const KERNEL_FEATURE_ITER_TARGET_UNIX = {
    key: "iter-target:unix"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/net/unix/af_unix.c"
}
const KERNEL_FEATURE_ITER_TARGET_IPV6_ROUTE = {
    key: "iter-target:ipv6_route"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/net/ipv6/route.c"
}
const KERNEL_FEATURE_ITER_TARGET_NETLINK = {
    key: "iter-target:netlink"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/net/netlink/af_netlink.c"
}
