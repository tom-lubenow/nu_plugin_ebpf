export const VERIFIER_DIFF_FIXTURES_3418_3420 = [
    {
        name: "task-storage-map-get-flags-zero"
        category: "language-surface"
        tags: [maps local-storage task-storage map-get flags accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let state = ($ctx.task | map-get task_state --kind task-storage --flags 0)'
            '  if $state {'
            '    $state | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "task-storage-map-get-init-flags-create"
        category: "language-surface"
        tags: [maps local-storage task-storage map-get init flags accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let state = ($ctx.task | map-get task_state --kind task-storage --init { hits: 0 } --flags 1)'
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
        name: "task-storage-map-get-rejects-invalid-flags"
        category: "language-surface"
        tags: [maps local-storage task-storage map-get flags reject]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let state = ($ctx.task | map-get task_state --kind task-storage --flags 2)'
            '  if $state {'
            '    $state | count'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "storage get helpers require arg3 flags to be 0 or BPF_LOCAL_STORAGE_GET_F_CREATE"
    }
]
