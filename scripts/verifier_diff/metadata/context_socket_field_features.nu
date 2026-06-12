const KERNEL_FEATURE_CTX_SK_REUSEPORT_PACKET_LEN = {
    key: "ctx:packet_len"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_REUSEPORT_DATA = {
    key: "ctx:data"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_REUSEPORT_DATA_END = {
    key: "ctx:data_end"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_REUSEPORT_ETH_PROTOCOL = {
    key: "ctx:eth_protocol"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_REUSEPORT_PROTOCOL = {
    key: "ctx:protocol"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_REUSEPORT_BIND_INANY = {
    key: "ctx:bind_inany"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_REUSEPORT_HASH = {
    key: "ctx:hash"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_REUSEPORT_SK = {
    key: "ctx:sk"
    min_kernel: "5.14"
    source: "https://github.com/torvalds/linux/blob/v5.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_REUSEPORT_MIGRATING_SK = {
    key: "ctx:migrating_sk"
    min_kernel: "5.14"
    source: "https://github.com/torvalds/linux/blob/v5.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SOCK_OPS_SKB_LEN = {
    key: "ctx:skb_len"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SOCK_OPS_SKB_TCP_FLAGS = {
    key: "ctx:skb_tcp_flags"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_HWTSTAMP = {
    key: "ctx:hwtstamp"
    min_kernel: "5.16"
    source: "https://github.com/torvalds/linux/blob/v5.16/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_TSTAMP_TYPE = {
    key: "ctx:tstamp_type"
    min_kernel: "5.18"
    source: "https://github.com/torvalds/linux/blob/v5.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SKB_HWTSTAMP = {
    key: "ctx:skb_hwtstamp"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_NETFILTER_STATE = {
    key: "ctx:state"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/net/netfilter/nf_bpf_link.c"
}
const KERNEL_FEATURE_CTX_NETFILTER_SKB = {
    key: "ctx:skb"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/net/netfilter/nf_bpf_link.c"
}
const KERNEL_FEATURE_CTX_NETFILTER_HOOK = {
    key: "ctx:hook"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/net/netfilter/nf_bpf_link.c"
}
const KERNEL_FEATURE_CTX_NETFILTER_PROTOCOL_FAMILY = {
    key: "ctx:pf"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/net/netfilter/nf_bpf_link.c"
}
const KERNEL_FEATURE_CTX_LIRC_SAMPLE = {
    key: "ctx:sample"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/drivers/media/rc/bpf-lirc.c"
}
const KERNEL_FEATURE_CTX_LIRC_VALUE = {
    key: "ctx:value"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/drivers/media/rc/bpf-lirc.c"
}
const KERNEL_FEATURE_CTX_LIRC_MODE = {
    key: "ctx:mode"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/drivers/media/rc/bpf-lirc.c"
}
const KERNEL_FEATURE_CTX_PERF_SAMPLE_PERIOD = {
    key: "ctx:sample_period"
    min_kernel: "4.9"
    source: "https://github.com/torvalds/linux/blob/v4.9/include/uapi/linux/bpf_perf_event.h"
}
const KERNEL_FEATURE_CTX_PERF_ADDR = {
    key: "ctx:addr"
    min_kernel: "5.0"
    source: "https://github.com/torvalds/linux/blob/v5.0/include/uapi/linux/bpf_perf_event.h"
}
