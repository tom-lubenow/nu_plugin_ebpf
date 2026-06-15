export const VERIFIER_DIFF_FIXTURES_3858_3858 = [
    {
        name: "map-delete-array-bool-key-direct-contains-false"
        category: "maps"
        tags: [maps map-define map-put map-delete map-contains arrays bool key accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_flags --kind hash --key-type "array{bool:2}" --value-type int --max-entries 1'
            '  let key = [true false]'
            '  42 | map-put keyed_flags $key --kind hash'
            '  $key | map-delete keyed_flags --kind hash'
            '  not ($key | map-contains keyed_flags --kind hash)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
