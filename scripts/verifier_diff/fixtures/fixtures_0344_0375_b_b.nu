const VERIFIER_DIFF_FIXTURES_0344_0375_B_B = [
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
