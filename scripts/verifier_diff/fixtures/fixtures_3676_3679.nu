export const VERIFIER_DIFF_FIXTURES_3676_3679 = [
    {
        name: "map-define-bloom-filter-array-record-list-value-type-push-contains"
        category: "maps"
        tags: [maps bloom-filter map-define records arrays list value-type map-push map-contains accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define typed_bloom_samples --kind bloom-filter --value-type "array{record{id:int,samples:list:int:2}:2}" --max-entries 16'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-push typed_bloom_samples --kind bloom-filter'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-contains typed_bloom_samples --kind bloom-filter'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-bloom-filter-array-record-list-builder-value-type-push-contains"
        category: "maps"
        tags: [maps bloom-filter map-define records arrays list append value-type map-push map-contains accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define typed_bloom_sample_build --kind bloom-filter --value-type "array{record{id:int,samples:list:int:2}:2}" --max-entries 16'
            '  let entries = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  $entries | map-push typed_bloom_sample_build --kind bloom-filter'
            '  $entries | map-contains typed_bloom_sample_build --kind bloom-filter'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-bloom-filter-array-record-string-builder-value-type-push-contains"
        category: "maps"
        tags: [maps bloom-filter map-define records arrays string append value-type map-push map-contains accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define typed_bloom_names --kind bloom-filter --value-type "array{record{id:int,name:string:15}:2}" --max-entries 16'
            '  let entries = ([] | append { id: 1 name: "aa" } | append { id: 2 name: "bbb" })'
            '  $entries | map-push typed_bloom_names --kind bloom-filter'
            '  $entries | map-contains typed_bloom_names --kind bloom-filter'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-bloom-filter-array-record-string-global-value-type-contains"
        category: "maps"
        tags: [maps bloom-filter map-define records arrays string globals value-type map-push map-contains accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define typed_bloom_names_global --kind bloom-filter --value-type "array{record{id:int,name:string:15}:2}" --max-entries 16'
            '  [{ id: 1 name: "aa" } { id: 2 name: "bbb" }] | global-define --type "array{record{id:int,name:string:15}:2}" bloom_name_query'
            '  let entries = (global-get bloom_name_query)'
            '  $entries | map-push typed_bloom_names_global --kind bloom-filter'
            '  $entries | map-contains typed_bloom_names_global --kind bloom-filter'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
