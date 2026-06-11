export const VERIFIER_DIFF_FIXTURES_3421_3422 = [
    {
        name: "task-storage-map-get-rejects-runtime-flags"
        category: "language-surface"
        tags: [maps local-storage task-storage map-get flags runtime reject]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let state = ($ctx.task | map-get task_state --kind task-storage --flags $flags)'
            '  if $state {'
            '    $state | count'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get --flags must be a compile-time integer literal"
    }
    {
        name: "task-storage-map-get-rejects-negative-flags"
        category: "language-surface"
        tags: [maps local-storage task-storage map-get flags reject]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let state = ($ctx.task | map-get task_state --kind task-storage --flags (-1))'
            '  if $state {'
            '    $state | count'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get --flags must be >= 0"
    }
]
