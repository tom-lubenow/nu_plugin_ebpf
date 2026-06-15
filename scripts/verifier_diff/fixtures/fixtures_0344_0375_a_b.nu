const VERIFIER_DIFF_FIXTURES_0344_0375_A_B = [
    {
        name: "queue-map-push-peek-record"
        category: "maps"
        tags: [maps queue map-push map-peek records accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: $ctx.arg0, cookie: 7 } | map-push recent_args --kind queue'
            '  let entry = (map-peek recent_args --kind queue)'
            '  if $entry {'
            '    $entry.pid | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "stack-map-push-pop-record"
        category: "maps"
        tags: [maps stack map-push map-pop records accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: $ctx.arg0, cookie: 7 } | map-push recent_args --kind stack'
            '  let entry = (map-pop recent_args --kind stack)'
            '  if $entry {'
            '    $entry.cookie | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-map-update-delete-helpers"
        category: "maps"
        tags: [maps helper-call map-update map-delete accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_update_elem" seen $key $value 0'
            '  helper-call "bpf_map_delete_elem" seen $key'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-map-update-rejects-invalid-flags"
        category: "maps"
        tags: [maps helper-call map-update flags reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_update_elem" seen $key $value 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_map_update_elem' requires arg3 flags"
    }
    {
        name: "raw-map-update-rejects-dynamic-flags"
        category: "maps"
        tags: [maps helper-call map-update flags reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  let value = "abcdefgh"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_map_update_elem" seen $key $value $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_map_update_elem' requires arg3 flags"
    }
    {
        name: "raw-queue-map-push-peek-pop-helpers"
        category: "maps"
        tags: [maps queue helper-call map-push map-peek map-pop accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_push_elem" recent_raw $value 0 --kind queue'
            '  helper-call "bpf_map_peek_elem" recent_raw $value --kind queue'
            '  helper-call "bpf_map_pop_elem" recent_raw $value --kind queue'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-queue-map-push-rejects-invalid-flags"
        category: "maps"
        tags: [maps queue helper-call map-push flags reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_push_elem" recent_raw $value 4 --kind queue'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_map_push_elem' requires arg2 flags"
    }
    {
        name: "raw-queue-map-push-rejects-dynamic-flags"
        category: "maps"
        tags: [maps queue helper-call map-push flags reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_map_push_elem" recent_raw $value $flags --kind queue'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_map_push_elem' requires arg2 flags"
    }
    {
        name: "bloom-filter-push-contains"
        category: "maps"
        tags: [maps bloom-filter map-push map-contains accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-push seen_args --kind bloom-filter'
            '  $ctx.arg0 | map-contains seen_args --kind bloom-filter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
