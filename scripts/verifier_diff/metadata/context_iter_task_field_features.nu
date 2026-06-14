const KERNEL_FEATURE_CTX_ITER_META = {
    key: "ctx:iter_meta"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_ITER_TASK = {
    key: "ctx:iter_task"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/task_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_TASK_VMA_TASK = {
    key: "ctx:iter_task"
    min_kernel: "5.12"
    source: "https://github.com/torvalds/linux/blob/v5.12/kernel/bpf/task_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_FD = {
    key: "ctx:iter_fd"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/task_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_FILE = {
    key: "ctx:iter_file"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/task_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_VMA = {
    key: "ctx:iter_vma"
    min_kernel: "5.12"
    source: "https://github.com/torvalds/linux/blob/v5.12/kernel/bpf/task_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_CGROUP = {
    key: "ctx:iter_cgroup"
    min_kernel: "6.1"
    source: "https://github.com/torvalds/linux/blob/v6.1/kernel/bpf/cgroup_iter.c"
}
