const PROGRAM_SURFACE_OBJECT_STORAGE_KERNEL_FEATURE_EXPECTATIONS = [
    {
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  $ctx.sk | map-get sock_state --kind sk-storage --init { hits: 0 }'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_storage_get"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  $ctx.sk | map-delete sock_state --kind sk-storage'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_storage_delete"]
    }
    {
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_inode | map-get inode_state --kind inode-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_inode_storage_get"]
    }
    {
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_inode | map-delete inode_state --kind inode-storage'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_inode_storage_delete"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-get cgrp_state --kind cgrp-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_cgrp_storage_get"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-delete cgrp_state --kind cgrp-storage'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_cgrp_storage_delete"]
    }
]
