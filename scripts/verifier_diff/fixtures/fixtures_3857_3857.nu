export const VERIFIER_DIFF_FIXTURES_3857_3857 = [
    {
        name: "map-push-bloom-filter-record-bool-array-direct-contains"
        category: "maps"
        tags: [maps bloom-filter map-define map-push map-contains records arrays bool accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define seen_flags --kind bloom-filter --value-type "record{flags:array{bool:2},id:u32}" --max-entries 16'
            '  let key = { flags: [true false] id: 7 }'
            '  $key | map-push seen_flags --kind bloom-filter'
            '  $key | map-contains seen_flags --kind bloom-filter'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
