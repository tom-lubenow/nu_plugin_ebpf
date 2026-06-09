const VERIFIER_DIFF_FIXTURES_2433_2433 = [
    {
        name: "storage-helper-rejects-declared-init-value-type-conflict"
        category: "maps"
        tags: [maps local-storage task-storage helper-call schema diagnostics reject]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  map-define task_state --kind task-storage --value-type u64'
            '  helper-call "bpf_task_storage_get" task_state $ctx.task { pid: $ctx.pid } 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "storage helper init value type for 'task_state' conflicts with declared map schema"
    }
]
