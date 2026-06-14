const PROGRAM_SURFACE_TASK_STORAGE_KERNEL_FEATURE_EXPECTATIONS = [
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-get task_state --kind task-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_task_storage_get"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  map-define task_state --kind task-storage --value-type "record{hits:u64}"'
            '  $ctx.task | map-get task_state --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_task_storage_get"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-delete task_state --kind task-storage'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_task_storage_delete"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-contains task_state --kind task-storage'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_task_storage_get"]
    }
]
