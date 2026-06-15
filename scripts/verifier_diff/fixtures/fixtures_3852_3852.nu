export const VERIFIER_DIFF_FIXTURES_3852_3852 = [
    {
        name: "map-define-record-bool-array-key-direct-put-get"
        category: "maps"
        tags: [maps map-define records arrays bool key map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_flags --kind hash --key-type "record{flags:array{bool:2}}" --value-type int'
            '  let key = { flags: [true false] }'
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
