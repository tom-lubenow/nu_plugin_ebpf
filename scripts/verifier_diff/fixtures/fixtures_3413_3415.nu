export const VERIFIER_DIFF_FIXTURES_3413_3415 = [
    {
        name: "map-put-dynamic-inner-map-flags-zero"
        category: "language-surface"
        tags: [maps map-in-map map-put dynamic-update flags accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type int --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  let inner = (0 | map-get outer_array)'
            '  if $inner {'
            '    99 | map-put $inner 7 --flags 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-put-dynamic-inner-map-flags-exist"
        category: "language-surface"
        tags: [maps map-in-map map-put dynamic-update flags accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type int --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  let inner = (0 | map-get outer_array)'
            '  if $inner {'
            '    99 | map-put $inner 7 --flags 2'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-put-dynamic-inner-map-rejects-invalid-flags"
        category: "language-surface"
        tags: [maps map-in-map map-put dynamic-update flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type int --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  let inner = (0 | map-get outer_array)'
            '  if $inner {'
            '    99 | map-put $inner 7 --flags 4'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_map_update_elem' requires arg3 flags to be BPF_ANY, BPF_NOEXIST, or BPF_EXIST"
    }
]
