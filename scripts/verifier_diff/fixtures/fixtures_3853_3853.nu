export const VERIFIER_DIFF_FIXTURES_3853_3853 = [
    {
        name: "map-define-array-bool-key-direct-put-get"
        category: "maps"
        tags: [maps map-define arrays bool key map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_flags --kind hash --key-type "array{bool:2}" --value-type int'
            '  let key = [true false]'
            '  42 | map-put keyed_flags $key --kind hash'
            '  let entry = ($key | map-get keyed_flags --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
