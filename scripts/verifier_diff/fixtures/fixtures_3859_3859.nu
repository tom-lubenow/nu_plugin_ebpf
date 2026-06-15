export const VERIFIER_DIFF_FIXTURES_3859_3859 = [
    {
        name: "map-delete-record-bool-array-key-direct-contains-false"
        category: "maps"
        tags: [maps map-define map-put map-delete map-contains records arrays bool key accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_flags --kind hash --key-type "record{flags:array{bool:2}}" --value-type int --max-entries 1'
            '  let key = { flags: [true false] }'
            '  42 | map-put keyed_flags $key --kind hash'
            '  $key | map-delete keyed_flags --kind hash'
            '  not ($key | map-contains keyed_flags --kind hash)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
