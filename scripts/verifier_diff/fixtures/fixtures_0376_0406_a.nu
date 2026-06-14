const VERIFIER_DIFF_FIXTURES_0376_0406_A = [
    {
        name: "raw-ima-hash-helpers"
        category: "helper-state"
        tags: [helper ima hash accept source metadata]
        requires: [kernel-btf]
        target: "lsm.s:file_open"
        program: [
            '{|ctx|'
            '  let file_hash = "0123456789012345"'
            '  let inode_hash = "0123456789012345"'
            '  helper-call "bpf_ima_file_hash" $ctx.arg.file $file_hash 16'
            '  helper-call "bpf_ima_inode_hash" $ctx.arg.file.f_inode $inode_hash 16'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "raw-cgrp-storage-get-helper"
        category: "maps"
        tags: [maps local-storage cgrp-storage helper-call accept source metadata]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_cgrp_storage_get" cgrp_state $ctx.current_cgroup 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-sk-storage-delete-helper"
        category: "maps"
        tags: [maps local-storage sk-storage helper-call accept source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk {'
            '    helper-call "bpf_sk_storage_delete" sock_state $sk'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-task-storage-delete-helper"
        category: "maps"
        tags: [maps local-storage task-storage helper-call accept source metadata]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_task_storage_delete" task_state $ctx.task'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-inode-storage-delete-helper"
        category: "maps"
        tags: [maps local-storage inode-storage helper-call accept source metadata]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_inode_storage_delete" inode_state $ctx.arg.file.f_inode'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-cgrp-storage-delete-helper"
        category: "maps"
        tags: [maps local-storage cgrp-storage helper-call accept source metadata]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_cgrp_storage_delete" cgrp_state $ctx.current_cgroup'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-task-storage-get-rejects-cgroup-owner"
        category: "maps"
        tags: [maps local-storage task-storage helper-call reject source metadata]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_task_storage_get" task_state $ctx.current_cgroup 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_task_storage_get' arg1 expects task pointer"
    }
    {
        name: "raw-task-storage-get-rejects-invalid-flags"
        category: "maps"
        tags: [maps local-storage task-storage helper-call flags reject source metadata]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_task_storage_get" task_state $ctx.task 0 2'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "storage get helpers require arg3 flags"
    }
    {
        name: "raw-task-storage-get-rejects-dynamic-flags"
        category: "maps"
        tags: [maps local-storage task-storage helper-call flags dynamic reject source metadata]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_task_storage_get" task_state $ctx.task 0 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "storage get helpers require arg3 flags"
    }
    {
        name: "raw-get-local-storage-rejects-deprecated-map"
        category: "maps"
        tags: [maps local-storage deprecated helper-call reject source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_local_storage" legacy_storage 0'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "deprecated-cgroup-storage; use cgrp-storage local-storage maps instead"
    }
    {
        name: "raw-get-local-storage-rejects-nonzero-flags"
        category: "maps"
        tags: [maps local-storage deprecated helper-call flags reject source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_local_storage" legacy_storage 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_local_storage' requires arg1 flags to be 0"
    }
    {
        name: "raw-get-local-storage-rejects-dynamic-flags"
        category: "maps"
        tags: [maps local-storage deprecated helper-call flags reject source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_get_local_storage" legacy_storage $flags'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_local_storage' requires arg1 flags to be 0"
    }
    {
        name: "task-storage-rejects-socket-owner"
        category: "maps"
        tags: [maps local-storage task-storage map-get source reject]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-get task_state --kind task-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_task_storage_get' arg1 expects task pointer"
    }
    {
        name: "sk-storage-rejects-task-owner"
        category: "maps"
        tags: [maps local-storage sk-storage map-get source reject]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-get sock_state --kind sk-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_storage_get' arg1 expects socket pointer"
    }
    {
        name: "inode-storage-rejects-task-owner"
        category: "maps"
        tags: [maps local-storage inode-storage map-get source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file | map-get inode_state --kind inode-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_inode_storage_get' arg1 expects inode pointer"
    }
]
