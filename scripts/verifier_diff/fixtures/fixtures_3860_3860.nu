export const VERIFIER_DIFF_FIXTURES_3860_3860 = [
    {
        name: "task-storage-map-get-init-direct-bool-array"
        category: "maps"
        tags: [maps local-storage task-storage map-define arrays bool map-get init accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  map-define task_bool_state --kind task-storage --value-type "array{bool:2}"'
            '  let state = ($ctx.task | map-get task_bool_state --kind task-storage --init [true false])'
            '  if $state {'
            '    (($state | get 0) and (not ($state | get 1)))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
