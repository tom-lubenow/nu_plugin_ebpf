export const VERIFIER_DIFF_FIXTURES_3644_3647 = [
    {
        name: "bloom-filter-array-record-list-field-push-contains"
        category: "maps"
        tags: [maps bloom-filter records arrays list map-push map-contains accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-push seen_sample_batches --kind bloom-filter'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-contains seen_sample_batches --kind bloom-filter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "bloom-filter-array-record-list-builder-push-contains"
        category: "maps"
        tags: [maps bloom-filter records arrays list append map-push map-contains accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entries = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  $entries | map-push seen_sample_batches_build --kind bloom-filter'
            '  $entries | map-contains seen_sample_batches_build --kind bloom-filter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "bloom-filter-array-record-string-builder-push-contains"
        category: "maps"
        tags: [maps bloom-filter records arrays string append map-push map-contains accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entries = ([] | append { id: 1 name: "aa" } | append { id: 2 name: "bbb" })'
            '  $entries | map-push seen_name_batches_build --kind bloom-filter'
            '  $entries | map-contains seen_name_batches_build --kind bloom-filter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "bloom-filter-array-record-string-field-contains"
        category: "maps"
        tags: [maps bloom-filter records arrays string map-contains accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 name: "aa" } { id: 2 name: "bbb" }] | map-contains seen_name_batches --kind bloom-filter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
