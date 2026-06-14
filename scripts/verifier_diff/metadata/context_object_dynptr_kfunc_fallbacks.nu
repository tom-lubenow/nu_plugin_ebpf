const OBJECT_DYNPTR_KFUNC_KERNEL_FEATURE_FALLBACKS = [
    { name: "bpf_cgroup_acquire", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_cgroup_ancestor", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_cgroup_from_id", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c" }
    { name: "bpf_cgroup_release", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_copy_from_user_dynptr", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_copy_from_user_str", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/helpers.c" }
    { name: "bpf_copy_from_user_task_dynptr", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_copy_from_user_task_str", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/helpers.c" }
    { name: "bpf_copy_from_user_task_str_dynptr", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_crypto_ctx_acquire", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/crypto.c" }
    { name: "bpf_crypto_ctx_create", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/crypto.c" }
    { name: "bpf_crypto_ctx_release", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/crypto.c" }
    { name: "bpf_crypto_decrypt", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/crypto.c" }
    { name: "bpf_crypto_encrypt", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/crypto.c" }
    { name: "bpf_dynptr_adjust", min_kernel: "6.5", source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/helpers.c" }
    { name: "bpf_dynptr_clone", min_kernel: "6.5", source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/helpers.c" }
    { name: "bpf_dynptr_copy", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/helpers.c" }
    { name: "bpf_dynptr_from_skb", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/net/core/filter.c" }
    { name: "bpf_dynptr_from_xdp", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/net/core/filter.c" }
    { name: "bpf_dynptr_is_null", min_kernel: "6.5", source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/helpers.c" }
    { name: "bpf_dynptr_is_rdonly", min_kernel: "6.5", source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/helpers.c" }
    { name: "bpf_dynptr_memset", min_kernel: "6.17", source: "https://github.com/torvalds/linux/blob/v6.17/kernel/bpf/helpers.c" }
    { name: "bpf_dynptr_size", min_kernel: "6.5", source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/helpers.c" }
    { name: "bpf_dynptr_slice", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c" }
    { name: "bpf_dynptr_slice_rdwr", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c" }
    { name: "bpf_get_task_exe_file", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/fs/bpf_fs_kfuncs.c" }
]
