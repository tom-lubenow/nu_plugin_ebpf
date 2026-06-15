export const VERIFIER_DIFF_FIXTURES_3856_3856 = [
    {
        name: "map-push-bloom-filter-array-bool-direct-contains"
        category: "maps"
        tags: [maps bloom-filter map-define map-push map-contains arrays bool accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define seen_flags --kind bloom-filter --value-type "array{bool:2}" --max-entries 16'
            '  let key = [true false]'
            '  $key | map-push seen_flags --kind bloom-filter'
            '  $key | map-contains seen_flags --kind bloom-filter'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
