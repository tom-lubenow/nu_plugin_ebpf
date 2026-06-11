export const VERIFIER_DIFF_FIXTURES_3405_3412 = [
    {
        name: "map-put-generic-hash-flags-zero"
        category: "language-surface"
        tags: [maps map-put hash flags accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put seen_args 0 --kind hash --flags 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-put-generic-hash-flags-noexist"
        category: "language-surface"
        tags: [maps map-put hash flags accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put seen_args 0 --kind hash --flags 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-put-generic-hash-flags-exist"
        category: "language-surface"
        tags: [maps map-put hash flags accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put seen_args 0 --kind hash --flags 2'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-put-generic-hash-rejects-invalid-flags"
        category: "language-surface"
        tags: [maps map-put hash flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put seen_args 0 --kind hash --flags 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_map_update_elem' requires arg3 flags to be BPF_ANY, BPF_NOEXIST, or BPF_EXIST"
    }
    {
        name: "map-push-queue-flags-zero"
        category: "language-surface"
        tags: [maps map-push queue flags accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-push recent_args --kind queue --flags 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-push-stack-flags-exist"
        category: "language-surface"
        tags: [maps map-push stack flags accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-push recent_args --kind stack --flags 2'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-push-queue-rejects-invalid-flags"
        category: "language-surface"
        tags: [maps map-push queue flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-push recent_args --kind queue --flags 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_map_push_elem' requires arg2 flags to be 0 or BPF_EXIST"
    }
    {
        name: "map-push-bloom-filter-rejects-invalid-flags"
        category: "language-surface"
        tags: [maps map-push bloom-filter flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-push seen_args --kind bloom-filter --flags 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_map_push_elem' requires arg2 flags to be 0 or BPF_EXIST"
    }
]
