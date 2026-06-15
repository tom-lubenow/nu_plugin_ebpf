const VERIFIER_DIFF_FIXTURES_1063_1093_A_B = [
    {
        name: "lwt-seg6local-store-bytes-helper"
        category: "helper-state"
        tags: [lwt helper-call seg6local accept source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  map-define seg6_bytes --kind array --value-type bytes:16 --max-entries 1'
            '  let bytes = (0 | map-get seg6_bytes --kind array)'
            '  if $bytes { helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes 16 }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-store-bytes-rejects-stale-data"
        category: "helper-state"
        tags: [lwt helper-call seg6local packet-bounds reject source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  let bytes = "0123456789abcdef"'
            '  helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes 16'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "lwt-seg6local-store-bytes-allows-reloaded-data"
        category: "helper-state"
        tags: [lwt helper-call seg6local packet-bounds accept source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  let bytes = "0123456789abcdef"'
            '  helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes 16'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-adjust-srh-helper"
        category: "helper-state"
        tags: [lwt helper-call seg6local accept source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  helper-call "bpf_lwt_seg6_adjust_srh" $ctx 0 4'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-action-helper"
        category: "helper-state"
        tags: [lwt helper-call seg6local accept source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  map-define seg6_action --kind array --value-type bytes:16 --max-entries 1'
            '  let param = (0 | map-get seg6_action --kind array)'
            '  if $param { helper-call "bpf_lwt_seg6_action" $ctx 2 $param 16 }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-store-bytes-rejects-small-buffer"
        category: "helper-state"
        tags: [lwt helper-call seg6local bounds reject source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  map-define seg6_bytes --kind array --value-type bytes:8 --max-entries 1'
            '  let bytes = (0 | map-get seg6_bytes --kind array)'
            '  if $bytes { helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes 16 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper lwt buffer requires 16 bytes"
    }
    {
        name: "lwt-seg6local-store-bytes-rejects-dynamic-small-buffer"
        category: "helper-state"
        tags: [lwt helper-call seg6local bounds dynamic reject source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  map-define seg6_bytes_dyn_short --kind array --value-type bytes:8 --max-entries 1'
            '  let bytes = (0 | map-get seg6_bytes_dyn_short --kind array)'
            '  if $bytes {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 8 } else { 16 })'
            '    helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes $size'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper lwt buffer requires 16 bytes"
    }
]
