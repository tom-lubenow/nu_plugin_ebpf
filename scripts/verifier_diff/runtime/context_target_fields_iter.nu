def target-iter-context-field-alias-kernel-feature [field: string target_text: string] {
    if ($target_text | str starts-with "iter:") {
        let iter_target = ($target_text | split row ":" | get 1)

        if $field == "meta" or $field == "iter_meta" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_META }
        }
        if $field == "task" or $field == "iter_task" {
            if $iter_target == "task_vma" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_TASK_VMA_TASK }
            }
            if $iter_target in ["task" "task_file"] {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_TASK }
            }
        }
        if ($field == "fd" or $field == "iter_fd") and $iter_target == "task_file" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_FD }
        }
        if ($field == "file" or $field == "iter_file") and $iter_target == "task_file" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_FILE }
        }
        if ($field == "vma" or $field == "iter_vma") and $iter_target == "task_vma" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_VMA }
        }
        if ($field == "cgroup" or $field == "iter_cgroup") and $iter_target == "cgroup" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_CGROUP }
        }
        if $field == "map" or $field == "iter_map" {
            if $iter_target == "bpf_map" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_MAP }
            }
            if $iter_target == "bpf_map_elem" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_MAP_ELEM_MAP }
            }
            if $iter_target == "bpf_sk_storage_map" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SK_STORAGE_MAP }
            }
            if $iter_target == "sockmap" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SOCKMAP_MAP }
            }
        }
        if $field == "key" or $field == "iter_key" {
            if $iter_target == "bpf_map_elem" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_MAP_KEY }
            }
            if $iter_target == "sockmap" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SOCKMAP_KEY }
            }
        }
        if $field == "value" or $field == "iter_value" {
            if $iter_target == "bpf_map_elem" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_MAP_VALUE }
            }
            if $iter_target == "bpf_sk_storage_map" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SK_STORAGE_VALUE }
            }
        }
        if $field == "sk" or $field == "sock" or $field == "iter_sock" {
            if $iter_target == "bpf_sk_storage_map" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SK_STORAGE_SOCK }
            }
            if $iter_target == "sockmap" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SOCKMAP_SOCK }
            }
        }
        if ($field == "prog" or $field == "iter_prog") and $iter_target == "bpf_prog" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_PROG }
        }
        if ($field == "link" or $field == "iter_link") and $iter_target == "bpf_link" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_LINK }
        }
        if ($field == "sk_common" or $field == "sock_common" or $field == "iter_sk_common") and $iter_target == "tcp" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_TCP_SK_COMMON }
        }
        if ($field == "udp_sk" or $field == "iter_udp_sk") and $iter_target == "udp" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UDP_SK }
        }
        if ($field == "unix_sk" or $field == "iter_unix_sk") and $iter_target == "unix" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UNIX_SK }
        }
        if $field == "uid" or $field == "iter_uid" {
            if $iter_target == "tcp" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_TCP_UID }
            }
            if $iter_target == "udp" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UDP_UID }
            }
            if $iter_target == "unix" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UNIX_UID }
            }
        }
        if ($field == "bucket" or $field == "iter_bucket") and $iter_target == "udp" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UDP_BUCKET }
        }
        if ($field == "rt" or $field == "route" or $field == "ipv6_route" or $field == "iter_ipv6_route") and $iter_target == "ipv6_route" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_IPV6_ROUTE }
        }
        if ($field == "ksym" or $field == "iter_ksym") and $iter_target == "ksym" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_KSYM }
        }
        if ($field == "netlink_sk" or $field == "iter_netlink_sk") and $iter_target == "netlink" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_NETLINK_SK }
        }
        if ($field == "cache" or $field == "kmem_cache" or $field == "iter_kmem_cache") and $iter_target == "kmem_cache" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_KMEM_CACHE }
        }
        if ($field == "dmabuf" or $field == "iter_dmabuf") and $iter_target == "dmabuf" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_DMABUF }
        }
    }

    { matched: false, feature: null }
}
