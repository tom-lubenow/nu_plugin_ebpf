export const VERIFIER_DIFF_FIXTURES_3757_3758 = [
    {
        name: "map-get-array-u64-find-length"
        category: "maps"
        tags: [maps map-define map-get arrays u64 find length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define wide_ports --kind array --value-type "array{u64:2}" --max-entries 1'
            '  let entry = (0 | map-get wide_ports --kind array)'
            '  if $entry {'
            '    ((($entry | find 0 | length) == 2))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u64-find-first-rejects"
        category: "globals"
        tags: [globals arrays u64 find first diagnostics reject global-define]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  (((global-get ports) | find 0 | first) == 0)'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "find on typed fixed arrays with u64 elements is supported only for metadata-only shape consumers"
    }
]
