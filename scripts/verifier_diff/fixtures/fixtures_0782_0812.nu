const VERIFIER_DIFF_FIXTURES_0782_0812 = [
    {
        name: "source-helper-sock-ops-cb-flags-set"
        category: "helper-state"
        tags: [sock-ops helper accept source metadata]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  helper-call "bpf_sock_ops_cb_flags_set" $ctx 1'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-trace-printk"
        category: "helper-state"
        tags: [helper trace-printk accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_trace_printk" "hello" 5'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-send-signal"
        category: "helper-state"
        tags: [helper signal accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_send_signal" 0'
            '  helper-call "bpf_send_signal_thread" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-per-cpu-pointers"
        category: "helper-state"
        tags: [helper per-cpu accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_per_cpu_ptr" $ctx 0'
            '  helper-call "bpf_this_cpu_ptr" $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-socket-conversions"
        category: "helper-state"
        tags: [tc cgroup-skb cgroup-sockopt helper socket accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk {'
            '    let full = (helper-call "bpf_sk_fullsock" $sk)'
            '    if $full { $full.family | count }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-tcp-sock-conversion"
        category: "helper-state"
        tags: [cgroup-sockopt helper socket accept source metadata]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk {'
            '    let tcp = (helper-call "bpf_tcp_sock" $sk)'
            '    if $tcp { $tcp.snd_cwnd | count }'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-listener-sock-conversion"
        category: "helper-state"
        tags: [cgroup-skb helper socket accept source metadata]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk {'
            '    let listener = (helper-call "bpf_get_listener_sock" $sk)'
            '    if $listener { $listener.family | count }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-sk-cgroup-ids"
        category: "helper-state"
        tags: [cgroup-skb helper socket cgroup accept source metadata]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk {'
            '    helper-call "bpf_sk_cgroup_id" $sk'
            '    helper-call "bpf_sk_ancestor_cgroup_id" $sk 0'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-task-and-file-pointer-helpers"
        category: "helper-state"
        tags: [fentry helper task file socket accept source metadata]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_task_pt_regs" $ctx.task'
            '  helper-call "bpf_sock_from_file" $ctx.arg.file'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-skc-socket-conversions"
        category: "helper-state"
        tags: [sk-lookup helper socket accept source metadata]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk {'
            '    helper-call "bpf_skc_to_tcp_sock" $sk'
            '    helper-call "bpf_skc_to_tcp6_sock" $sk'
            '    helper-call "bpf_skc_to_tcp_timewait_sock" $sk'
            '    helper-call "bpf_skc_to_tcp_request_sock" $sk'
            '    helper-call "bpf_skc_to_udp6_sock" $sk'
            '    helper-call "bpf_skc_to_mptcp_sock" $sk'
            '    helper-call "bpf_skc_to_unix_sock" $sk'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "tc-skb-get-xfrm-state-helper-rejects-non-tc"
        category: "helper-state"
        tags: [helper xfrm reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let state = "0123456789abcdef"'
            '  helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state 16 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_get_xfrm_state' is only valid in tc_action, tc, tcx, and netkit programs"
    }
    {
        name: "tc-skb-get-xfrm-state-helper-rejects-nonzero-flags"
        category: "helper-state"
        tags: [tc helper xfrm flags reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let state = "0123456789abcdef"'
            '  helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state 16 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_get_xfrm_state' requires arg4 = 0"
    }
    {
        name: "tc-skb-get-xfrm-state-helper-rejects-small-buffer"
        category: "helper-state"
        tags: [tc helper xfrm bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define xfrm_states --kind array --value-type "bytes:8" --max-entries 1'
            '  let state = (0 | map-get xfrm_states --kind array)'
            '  if $state { helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state 16 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper skb_get_xfrm_state xfrm_state requires 16 bytes"
    }
    {
        name: "tc-skb-get-xfrm-state-helper-rejects-dynamic-small-buffer"
        category: "helper-state"
        tags: [tc helper xfrm bounds dynamic reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define xfrm_states_dyn_short --kind array --value-type "bytes:8" --max-entries 1'
            '  let state = (0 | map-get xfrm_states_dyn_short --kind array)'
            '  if $state {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 8 } else { 16 })'
            '    helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state $size 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper skb_get_xfrm_state xfrm_state requires 16 bytes"
    }
    {
        name: "tc-egress-helper-backed-context"
        category: "context-surface"
        tags: [tc context helper-backed egress]
        requires: [loopback-interface]
        target: "tc:lo:egress"
        program: [
            '{|ctx|'
            '  ($ctx.skb_cgroup_id + $ctx.skb_ancestor_cgroup_id.0 + $ctx.route_realm + $ctx.cgroup_classid + $ctx.netns_cookie) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-ingress-rejects-egress-context"
        category: "context-policy"
        tags: [tc context reject egress-only]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.skb_cgroup_id | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.skb_cgroup_id is only available on tc/tcx egress programs"
    }
    {
        name: "tcx-ingress-skb-context-write"
        category: "context-surface"
        tags: [tcx context packet writable]
        requires: [loopback-interface]
        target: "tcx:lo:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.tc_classid + $ctx.hash + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.mark = 7'
            '  $ctx.queue_mapping = 1'
            '  $ctx.priority = 3'
            '  $ctx.tc_index = 2'
            '  $ctx.cb.3 = 9'
            '  $ctx.tc_classid = 42'
            '  $ctx.tstamp = 123'
            '  "next"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tcx-ingress-context-socket-write"
        category: "context-surface"
        tags: [tcx context writable socket]
        requires: [loopback-interface]
        target: "tcx:lo:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "next"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tcx-egress-helper-backed-context"
        category: "context-surface"
        tags: [tcx context helper-backed egress]
        requires: [loopback-interface]
        target: "tcx:lo:egress"
        program: [
            '{|ctx|'
            '  ($ctx.skb_cgroup_id + $ctx.skb_ancestor_cgroup_id.0 + $ctx.route_realm + $ctx.cgroup_classid + $ctx.netns_cookie) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tcx-ingress-rejects-egress-context"
        category: "context-policy"
        tags: [tcx context reject egress-only]
        requires: [loopback-interface]
        target: "tcx:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.skb_cgroup_id | count'
            '  "next"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.skb_cgroup_id is only available on tc/tcx egress programs"
    }
    {
        name: "tcx-egress-rejects-context-socket-write"
        category: "context-policy"
        tags: [tcx context writable socket reject egress-only]
        requires: [loopback-interface]
        target: "tcx:lo:egress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_assign' is only valid in tc/tcx ingress programs"
    }
    {
        name: "netkit-primary-skb-context-write"
        category: "context-surface"
        tags: [netkit context packet writable]
        requires: [loopback-interface]
        target: "netkit:lo:primary"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.tc_classid + $ctx.hash + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.mark = 7'
            '  $ctx.queue_mapping = 1'
            '  $ctx.priority = 3'
            '  $ctx.tc_index = 2'
            '  $ctx.cb.3 = 9'
            '  $ctx.tc_classid = 42'
            '  $ctx.tstamp = 123'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "netkit-rejects-context-socket-write"
        category: "context-policy"
        tags: [netkit context writable socket reject]
        requires: [loopback-interface]
        target: "netkit:lo:primary"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_assign' is only valid in tc_action, tc, tcx, and sk_lookup programs"
    }
    {
        name: "netkit-peer-skb-context"
        category: "context-surface"
        tags: [netkit context packet]
        requires: [loopback-interface]
        target: "netkit:lo:peer"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.hash + $ctx.ingress_ifindex + $ctx.queue_mapping) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "netkit-rejects-egress-context"
        category: "context-policy"
        tags: [netkit context reject egress-only]
        requires: [loopback-interface]
        target: "netkit:lo:primary"
        program: [
            '{|ctx|'
            '  $ctx.skb_cgroup_id | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.skb_cgroup_id is only available on tc_action, tc:egress, and tcx:egress programs"
    }
    {
        name: "xdp-rejects-pid-context"
        category: "context-policy"
        tags: [xdp reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.pid | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.pid is not available on xdp programs"
    }
    {
        name: "xdp-rejects-egress-ifindex-on-interface"
        category: "context-policy"
        tags: [xdp reject devmap]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.egress_ifindex | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.egress_ifindex is only available on xdp:devmap secondary programs"
    }
    {
        name: "xdp-rejects-egress-ifindex-on-cpumap"
        category: "context-policy"
        tags: [xdp reject cpumap devmap]
        target: "xdp:cpumap"
        program: [
            '{|ctx|'
            '  $ctx.egress_ifindex | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.egress_ifindex is only available on xdp:devmap secondary programs"
    }
    {
        name: "socket-filter-rejects-direct-data"
        category: "context-policy"
        tags: [socket-filter reject]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  $ctx.data | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.data is not available on socket_filter programs"
    }
    {
        name: "socket-filter-tcp6-context"
        category: "context-surface"
        tags: [socket-filter context ipv6]
        target: "socket_filter:tcp6:[::1]:8080"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.socket_cookie + $ctx.sk.family) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "socket-filter-rich-skb-context"
        category: "context-surface"
        tags: [socket-filter context packet source metadata]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.ingress_ifindex + $ctx.pkt_type + $ctx.queue_mapping + $ctx.protocol + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.tc_index + $ctx.hash + $ctx.mark + $ctx.priority) | count'
            '  ($ctx.socket_cookie + $ctx.socket_uid + $ctx.sk.family + $ctx.cb.0) | count'
            '  "keep"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
