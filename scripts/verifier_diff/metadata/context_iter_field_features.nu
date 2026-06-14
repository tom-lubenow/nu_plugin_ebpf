const KERNEL_FEATURE_CTX_ITER_PROG = {
    key: "ctx:iter_prog"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/kernel/bpf/prog_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_LINK = {
    key: "ctx:iter_link"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/kernel/bpf/link_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_KSYM = {
    key: "ctx:iter_ksym"
    min_kernel: "6.0"
    source: "https://github.com/torvalds/linux/blob/v6.0/kernel/kallsyms.c"
}
const KERNEL_FEATURE_CTX_ITER_KMEM_CACHE = {
    key: "ctx:iter_kmem_cache"
    min_kernel: "6.13"
    source: "https://github.com/torvalds/linux/blob/v6.13/kernel/bpf/kmem_cache_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_DMABUF = {
    key: "ctx:iter_dmabuf"
    min_kernel: "6.16"
    source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/dmabuf_iter.c"
}
