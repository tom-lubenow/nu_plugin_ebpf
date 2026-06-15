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
]
