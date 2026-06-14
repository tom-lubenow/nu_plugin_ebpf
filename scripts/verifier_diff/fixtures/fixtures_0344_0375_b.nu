const VERIFIER_DIFF_FIXTURES_0344_0375_B = [
    {
        name: "per-cpu-hash-map-put-get"
        category: "maps"
        tags: [maps per-cpu-hash map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put cpu_seen 0 --kind per-cpu-hash'
            '  let entry = (0 | map-get cpu_seen --kind per-cpu-hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lru-per-cpu-hash-map-put-delete"
        category: "maps"
        tags: [maps lru-per-cpu-hash map-put map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put lru_cpu_seen 0 --kind lru-per-cpu-hash'
            '  0 | map-delete lru_cpu_seen --kind lru-per-cpu-hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "task-storage-map-get-init"
        category: "maps"
        tags: [maps local-storage task-storage map-get accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let state = ($ctx.task | map-get task_state --kind task-storage --init { hits: 0 })'
            '  if $state {'
            '    $state.hits | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "task-storage-map-delete"
        category: "maps"
        tags: [maps local-storage task-storage map-delete accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-delete task_state --kind task-storage'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "task-storage-map-contains"
        category: "maps"
        tags: [maps local-storage task-storage map-contains accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  if ($ctx.task | map-contains task_state --kind task-storage) {'
            '    1 | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-storage-map-contains"
        category: "maps"
        tags: [maps local-storage sk-storage map-contains accept]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  $ctx.sk | map-contains sock_state --kind sk-storage'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-storage-map-get-init"
        category: "maps"
        tags: [maps local-storage sk-storage map-get accept]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  let state = ($ctx.sk | map-get sock_state --kind sk-storage --init { hits: 0 })'
            '  if $state {'
            '    $state.hits | count'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-storage-map-delete"
        category: "maps"
        tags: [maps local-storage sk-storage map-delete accept]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk {'
            '    $sk | map-delete sock_state --kind sk-storage'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "inode-storage-map-delete"
        category: "maps"
        tags: [maps local-storage inode-storage map-delete accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_inode | map-delete inode_state --kind inode-storage'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "inode-storage-map-get-init"
        category: "maps"
        tags: [maps local-storage inode-storage map-get accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let state = ($ctx.arg.file.f_inode | map-get inode_state --kind inode-storage --init { hits: 0 })'
            '  if $state {'
            '    $state.hits | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgrp-storage-map-contains"
        category: "maps"
        tags: [maps local-storage cgrp-storage map-contains accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-contains cgrp_state --kind cgrp-storage'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgrp-storage-map-get-init"
        category: "maps"
        tags: [maps local-storage cgrp-storage map-get accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let state = ($ctx.current_cgroup | map-get cgrp_state --kind cgrp-storage --init { hits: 0 })'
            '  if $state {'
            '    $state.hits | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgrp-storage-map-delete"
        category: "maps"
        tags: [maps local-storage cgrp-storage map-delete accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-delete cgrp_state --kind cgrp-storage'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-sk-storage-get-helper"
        category: "maps"
        tags: [maps local-storage sk-storage helper-call accept source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  helper-call "bpf_sk_storage_get" sock_state $ctx.sk 0 0'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-task-storage-get-helper"
        category: "maps"
        tags: [maps local-storage task-storage helper-call accept source metadata]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_task_storage_get" task_state $ctx.task 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-inode-storage-get-helper"
        category: "maps"
        tags: [maps local-storage inode-storage helper-call accept source metadata]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_inode_storage_get" inode_state $ctx.arg.file.f_inode 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
