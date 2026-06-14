const VERIFIER_DIFF_FIXTURES_0719_0750_B = [
    {
        name: "xdp-fib-lookup-helper"
        category: "helper-state"
        tags: [xdp helper fib accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-fib-lookup-rejects-invalid-flags"
        category: "helper-state"
        tags: [xdp helper fib flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 64 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_fib_lookup' requires arg3 flags"
    }
    {
        name: "xdp-fib-lookup-rejects-dynamic-flags"
        category: "helper-state"
        tags: [xdp helper fib flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 $flags }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_fib_lookup' requires arg3 flags"
    }
    {
        name: "xdp-fib-lookup-rejects-small-params-buffer"
        category: "helper-state"
        tags: [xdp helper fib bounds reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:8 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper fib_lookup params requires 64 bytes"
    }
    {
        name: "sk-skb-fib-lookup-rejects-program"
        category: "helper-state"
        tags: [sk-skb helper fib program-policy reject source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_fib_lookup' is only valid in xdp, tc_action, tc, tcx, and netkit programs"
    }
    {
        name: "xdp-check-mtu-helper"
        category: "helper-state"
        tags: [xdp helper mtu accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 0 }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-check-mtu-rejects-nonzero-flags"
        category: "helper-state"
        tags: [xdp helper mtu flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 1 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_check_mtu' requires arg4 = 0 in xdp programs"
    }
    {
        name: "xdp-check-mtu-rejects-dynamic-flags"
        category: "helper-state"
        tags: [xdp helper mtu flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 $flags }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_check_mtu' requires arg4 = 0 in xdp programs"
    }
    {
        name: "tc-check-mtu-helper"
        category: "helper-state"
        tags: [tc helper mtu accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 1 }'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-check-mtu-rejects-small-mtu-len"
        category: "helper-state"
        tags: [tc helper mtu bounds reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:2 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 0 }'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper check_mtu mtu_len requires 4 bytes"
    }
    {
        name: "sk-skb-check-mtu-rejects-program"
        category: "helper-state"
        tags: [sk-skb helper mtu program-policy reject source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 0 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_check_mtu' is only valid in xdp, tc_action, tc, tcx, and netkit programs"
    }
    {
        name: "tc-skb-get-tunnel-key-helper"
        category: "helper-state"
        tags: [tc helper tunnel accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_key --kind array --value-type bytes:44 --max-entries 1'
            '  let key = (0 | map-get tunnel_key --kind array)'
            '  if $key { helper-call "bpf_skb_get_tunnel_key" $ctx $key 44 0 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-get-tunnel-key-rejects-invalid-flags"
        category: "helper-state"
        tags: [tc helper tunnel flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_key --kind array --value-type bytes:44 --max-entries 1'
            '  let key = (0 | map-get tunnel_key --kind array)'
            '  if $key { helper-call "bpf_skb_get_tunnel_key" $ctx $key 44 2 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_get_tunnel_key' requires arg3 flags"
    }
    {
        name: "tc-skb-get-tunnel-key-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper tunnel flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_key --kind array --value-type bytes:44 --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let key = (0 | map-get tunnel_key --kind array)'
            '  if $key { helper-call "bpf_skb_get_tunnel_key" $ctx $key 44 $flags }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_get_tunnel_key' requires arg3 flags"
    }
    {
        name: "tc-skb-get-tunnel-opt-helper"
        category: "helper-state"
        tags: [tc helper tunnel accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_opt --kind array --value-type bytes:16 --max-entries 1'
            '  let opt = (0 | map-get tunnel_opt --kind array)'
            '  if $opt { helper-call "bpf_skb_get_tunnel_opt" $ctx $opt 16 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-set-tunnel-key-helper"
        category: "helper-state"
        tags: [tc helper tunnel accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_key --kind array --value-type bytes:44 --max-entries 1'
            '  let key = (0 | map-get tunnel_key --kind array)'
            '  if $key { helper-call "bpf_skb_set_tunnel_key" $ctx $key 44 0 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
