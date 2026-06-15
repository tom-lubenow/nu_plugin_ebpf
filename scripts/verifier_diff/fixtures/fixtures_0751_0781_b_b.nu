const VERIFIER_DIFF_FIXTURES_0751_0781_B_B = [
    {
        name: "xdp-load-bytes-helper"
        category: "helper-state"
        tags: [xdp helper bytes accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define scratch --kind array --value-type bytes:8 --max-entries 1'
            '  let dst = (0 | map-get scratch --kind array)'
            '  if $dst { helper-call "bpf_xdp_load_bytes" $ctx 0 $dst 8 }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-store-bytes-preserves-packet-data"
        category: "helper-state"
        tags: [xdp helper bytes packet-bounds accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  let bytes = "x"'
            '  helper-call "bpf_xdp_store_bytes" $ctx 0 $bytes 1'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-store-bytes-rejects-small-source-buffer"
        category: "helper-state"
        tags: [xdp helper bytes bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define scratch --kind array --value-type bytes:1 --max-entries 1'
            '  let bytes = (0 | map-get scratch --kind array)'
            '  if $bytes { helper-call "bpf_xdp_store_bytes" $ctx 0 $bytes 8 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper xdp_bytes buf requires 8 bytes"
    }
    {
        name: "xdp-store-bytes-rejects-dynamic-small-source-buffer"
        category: "helper-state"
        tags: [xdp helper bytes bounds dynamic reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define scratch_dyn_short --kind array --value-type bytes:1 --max-entries 1'
            '  let bytes = (0 | map-get scratch_dyn_short --kind array)'
            '  if $bytes {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 1 } else { 8 })'
            '    helper-call "bpf_xdp_store_bytes" $ctx 0 $bytes $size'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper xdp_bytes buf requires 8 bytes"
    }
    {
        name: "source-helper-xdp-adjust-and-buffer-len"
        category: "helper-state"
        tags: [xdp helper adjust-packet accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  helper-call "bpf_xdp_adjust_head" $ctx 0'
            '  helper-call "bpf_xdp_adjust_meta" $ctx 0'
            '  helper-call "bpf_xdp_adjust_tail" $ctx 0'
            '  let len = (helper-call "bpf_xdp_get_buff_len" $ctx)'
            '  $len | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-xdp-adjust-rejects-non-xdp-context"
        category: "helper-state"
        tags: [xdp helper adjust-packet program-policy reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_xdp_adjust_head" $ctx 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_xdp_adjust_head' is only valid in xdp programs"
    }
    {
        name: "source-helper-tc-skb-hash-csum-and-cgroup"
        category: "helper-state"
        tags: [tc helper skb cgroup accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_hash_recalc" $ctx'
            '  helper-call "bpf_csum_level" $ctx 0'
            '  helper-call "bpf_set_hash" $ctx 0'
            '  helper-call "bpf_skb_under_cgroup" $ctx tracked_cgroups 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-current-task-under-cgroup"
        category: "helper-state"
        tags: [helper current cgroup accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  helper-call "bpf_current_task_under_cgroup" tracked_cgroups 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-sk-msg-byte-count"
        category: "helper-state"
        tags: [sk-msg helper bytes accept source metadata]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  helper-call "bpf_msg_apply_bytes" $ctx 8'
            '  helper-call "bpf_msg_cork_bytes" $ctx 8'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
]
