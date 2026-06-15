const VERIFIER_DIFF_FIXTURES_0501_0531_A = [
    {
        name: "source-helper-netns-cookie-rejects-xdp"
        category: "helper-state"
        tags: [helper netns cookie program-policy reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_netns_cookie" $ctx'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_netns_cookie' is only valid in socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sock_ops, and sk_msg programs"
    }
    {
        name: "source-helper-cgroup-sysctl-raw-helpers"
        category: "helper-state"
        tags: [helper sysctl cgroup-sysctl accept source metadata]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef"'
            '  helper-call "bpf_sysctl_get_name" $ctx $buf 16 1'
            '  helper-call "bpf_sysctl_get_current_value" $ctx $buf 16'
            '  helper-call "bpf_sysctl_get_new_value" $ctx $buf 16'
            '  helper-call "bpf_sysctl_set_new_value" $ctx $buf 1'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-cgroup-sysctl-rejects-invalid-name-flags"
        category: "helper-state"
        tags: [helper sysctl cgroup-sysctl flags reject source metadata]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef"'
            '  helper-call "bpf_sysctl_get_name" $ctx $buf 16 2'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sysctl_get_name' requires arg3 flags"
    }
    {
        name: "source-helper-cgroup-sysctl-rejects-dynamic-name-flags"
        category: "helper-state"
        tags: [helper sysctl cgroup-sysctl flags reject source metadata]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_sysctl_get_name" $ctx $buf 16 $flags'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sysctl_get_name' requires arg3 flags"
    }
    {
        name: "source-helper-cgroup-sysctl-rejects-short-map-buffer"
        category: "helper-state"
        tags: [helper sysctl cgroup-sysctl map-bounds reject source metadata]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  map-define sysctl_buf_short --kind array --value-type bytes:4 --max-entries 1'
            '  let buf = (0 | map-get sysctl_buf_short)'
            '  if $buf {'
            '    helper-call "bpf_sysctl_get_current_value" $ctx $buf 8'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper sysctl_get_current_value buf requires 8 bytes"
    }
    {
        name: "source-helper-cgroup-sysctl-rejects-dynamic-short-map-buffer"
        category: "helper-state"
        tags: [helper sysctl cgroup-sysctl map-bounds dynamic reject source metadata]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  map-define sysctl_buf_dyn_short --kind array --value-type bytes:4 --max-entries 1'
            '  let buf = (0 | map-get sysctl_buf_dyn_short)'
            '  if $buf {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 4 } else { 8 })'
            '    helper-call "bpf_sysctl_get_current_value" $ctx $buf $size'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper sysctl_get_current_value buf requires 8 bytes"
    }
    {
        name: "source-helper-cgroup-sysctl-rejects-xdp"
        category: "helper-state"
        tags: [helper sysctl program-policy reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let buf = "01234567"'
            '  helper-call "bpf_sysctl_get_current_value" $ctx $buf 8'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sysctl_get_current_value' is only valid in cgroup_sysctl programs"
    }
]
