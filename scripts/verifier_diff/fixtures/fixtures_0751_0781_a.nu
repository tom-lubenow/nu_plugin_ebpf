const VERIFIER_DIFF_FIXTURES_0751_0781_A = [
    {
        name: "tc-skb-set-tunnel-key-rejects-invalid-flags"
        category: "helper-state"
        tags: [tc helper tunnel flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_key --kind array --value-type bytes:44 --max-entries 1'
            '  let key = (0 | map-get tunnel_key --kind array)'
            '  if $key { helper-call "bpf_skb_set_tunnel_key" $ctx $key 44 32 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tunnel_key' requires arg3 flags"
    }
    {
        name: "tc-skb-set-tunnel-key-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper tunnel flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_key --kind array --value-type bytes:44 --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let key = (0 | map-get tunnel_key --kind array)'
            '  if $key { helper-call "bpf_skb_set_tunnel_key" $ctx $key 44 $flags }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tunnel_key' requires arg3 flags"
    }
    {
        name: "tc-skb-set-tunnel-opt-helper"
        category: "helper-state"
        tags: [tc helper tunnel accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_opt --kind array --value-type bytes:16 --max-entries 1'
            '  let opt = (0 | map-get tunnel_opt --kind array)'
            '  if $opt { helper-call "bpf_skb_set_tunnel_opt" $ctx $opt 16 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-set-tunnel-opt-accepts-dynamic-aligned-size"
        category: "helper-state"
        tags: [tc helper tunnel size dynamic accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_opt_dyn_ok --kind array --value-type bytes:16 --max-entries 1'
            '  let opt = (0 | map-get tunnel_opt_dyn_ok --kind array)'
            '  if $opt {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 8 } else { 16 })'
            '    helper-call "bpf_skb_set_tunnel_opt" $ctx $opt $size'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "tc-skb-set-tunnel-opt-rejects-small-buffer"
        category: "helper-state"
        tags: [tc helper tunnel bounds reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_opt --kind array --value-type bytes:8 --max-entries 1'
            '  let opt = (0 | map-get tunnel_opt --kind array)'
            '  if $opt { helper-call "bpf_skb_set_tunnel_opt" $ctx $opt 16 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper skb_tunnel buffer requires 16 bytes"
    }
    {
        name: "tc-skb-set-tunnel-opt-rejects-dynamic-unaligned-size"
        category: "helper-state"
        tags: [tc helper tunnel size dynamic reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_opt_dyn_bad --kind array --value-type bytes:16 --max-entries 1'
            '  let opt = (0 | map-get tunnel_opt_dyn_bad --kind array)'
            '  if $opt {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 8 } else { 10 })'
            '    helper-call "bpf_skb_set_tunnel_opt" $ctx $opt $size'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tunnel_opt' requires arg2 size to be a multiple of 4"
    }
    {
        name: "tc-skb-set-tunnel-opt-rejects-dynamic-small-buffer"
        category: "helper-state"
        tags: [tc helper tunnel bounds dynamic reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_opt_dyn_short --kind array --value-type bytes:8 --max-entries 1'
            '  let opt_a = (0 | map-get tunnel_opt_dyn_short --kind array)'
            '  let opt_b = (0 | map-get tunnel_opt_dyn_short --kind array)'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let opt = (if $selector == 0 { $opt_a } else { $opt_b })'
            '  if $opt { helper-call "bpf_skb_set_tunnel_opt" $ctx $opt 16 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper skb_tunnel buffer requires 16 bytes"
    }
    {
        name: "tc-skb-load-bytes-relative-helper"
        category: "helper-state"
        tags: [tc helper skb-load-bytes accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define rel_bytes --kind array --value-type bytes:8 --max-entries 1'
            '  let dst = (0 | map-get rel_bytes --kind array)'
            '  if $dst { helper-call "bpf_skb_load_bytes_relative" $ctx 0 $dst 8 0 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-load-bytes-relative-rejects-invalid-start"
        category: "helper-state"
        tags: [tc helper skb-load-bytes flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define rel_bytes --kind array --value-type bytes:8 --max-entries 1'
            '  let dst = (0 | map-get rel_bytes --kind array)'
            '  if $dst { helper-call "bpf_skb_load_bytes_relative" $ctx 0 $dst 8 2 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_load_bytes_relative' requires arg4 start_header"
    }
    {
        name: "tc-skb-load-bytes-relative-rejects-dynamic-start"
        category: "helper-state"
        tags: [tc helper skb-load-bytes flags dynamic reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define rel_bytes --kind array --value-type bytes:8 --max-entries 1'
            '  let dst = (0 | map-get rel_bytes --kind array)'
            '  let start = (helper-call "bpf_get_prandom_u32")'
            '  if $dst { helper-call "bpf_skb_load_bytes_relative" $ctx 0 $dst 8 $start }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_load_bytes_relative' requires arg4 start_header"
    }
]
