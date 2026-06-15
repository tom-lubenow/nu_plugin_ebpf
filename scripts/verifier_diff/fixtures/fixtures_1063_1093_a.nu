const VERIFIER_DIFF_FIXTURES_1063_1093_A = [
    {
        name: "lwt-xmit-rejects-tc-classid-context"
        category: "context-policy"
        tags: [lwt reject context]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  $ctx.tc_classid | count'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.tc_classid is only available on tc_action, tc, tcx, and netkit programs"
    }
    {
        name: "lwt-xmit-rejects-socket-context"
        category: "context-policy"
        tags: [lwt reject context socket]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  $ctx.sk.family | count'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is only available on socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sk_lookup, sk_reuseport, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
    }
    {
        name: "lwt-push-encap-rejects-non-lwt-program"
        category: "helper-policy"
        tags: [lwt helper-call reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_lwt_push_encap" $ctx 0 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_lwt_push_encap' is only valid in lwt_in and lwt_xmit programs"
    }
    {
        name: "lwt-xmit-push-encap-helper"
        category: "helper-state"
        tags: [lwt helper-call accept source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  map-define encap_hdr --kind array --value-type bytes:16 --max-entries 1'
            '  let hdr = (0 | map-get encap_hdr --kind array)'
            '  if $hdr { helper-call "bpf_lwt_push_encap" $ctx 2 $hdr 16 }'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-push-encap-rejects-stale-data"
        category: "helper-state"
        tags: [lwt helper-call packet-bounds reject source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  let hdr = "0123456789abcdef"'
            '  helper-call "bpf_lwt_push_encap" $ctx 2 $hdr 16'
            '  ($data | get 0) | count'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "lwt-xmit-push-encap-allows-reloaded-data"
        category: "helper-state"
        tags: [lwt helper-call packet-bounds accept source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  let hdr = "0123456789abcdef"'
            '  helper-call "bpf_lwt_push_encap" $ctx 2 $hdr 16'
            '  ($ctx.data | get 0) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
]
