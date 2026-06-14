const VERIFIER_DIFF_FIXTURES_0876_0906_A = [
    {
        name: "flow-dissector-user-function-record-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable user-function record source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  def wrap [keys] { { keys: $keys } }'
            '  let keys = $ctx.flow_keys'
            '  mut rec = (wrap $keys)'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-rejects-flow-key-root-write"
        category: "context-surface"
        tags: [flow-dissector reject context writable]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.flow_keys = 1'
            '  "parsed"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a scalar field, not the root context pointer"
    }
    {
        name: "flow-dissector-rejects-flow-key-aggregate-write"
        category: "context-surface"
        tags: [flow-dissector reject context writable]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.flow_keys.ipv6_dst = 1'
            '  "parsed"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a scalar field, not Array"
    }
    {
        name: "flow-dissector-packet-context"
        category: "context-surface"
        tags: [flow-dissector context packet]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  ($ctx.data | get 0) | count'
            '  "fallback"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-rejects-packet-data-write"
        category: "context-policy"
        tags: [flow-dissector reject context packet writable]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.0 = 1'
            '  "parsed"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "direct packet writes are not supported on flow_dissector programs"
    }
    {
        name: "flow-dissector-rejects-bound-packet-data-write"
        category: "context-policy"
        tags: [flow-dissector reject context packet writable alias]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut data = $ctx.data'
            '  $data.0 = 1'
            '  "parsed"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "direct packet writes are not supported on flow_dissector programs"
    }
    {
        name: "flow-dissector-rejects-skb-packet-len-context"
        category: "context-policy"
        tags: [flow-dissector reject context]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.packet_len | count'
            '  "fallback"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.packet_len is not available on flow_dissector programs"
    }
    {
        name: "flow-dissector-rejects-socket-context"
        category: "context-policy"
        tags: [flow-dissector reject context socket]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.sk.family | count'
            '  "fallback"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is only available on socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sk_lookup, sk_reuseport, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
    }
    {
        name: "flow-dissector-rejects-flow-keys-helper-buffer"
        category: "context-policy"
        tags: [flow-dissector reject helper-call]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_load_bytes" $ctx 0 $ctx.flow_keys 4'
            '  "fallback"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects pointer in [Stack, Map], got Context"
    }
    {
        name: "flow-dissector-rejects-flow-keys-kernel-helper-arg"
        category: "context-policy"
        tags: [flow-dissector reject helper-call]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  map-define kptr_slots --kind hash --value-type "record{task:kptr:task_struct}"'
            '  let entry = (0 | map-get kptr_slots --kind hash)'
            '  if $entry { helper-call "bpf_kptr_xchg" $entry.task $ctx.flow_keys | count }'
            '  "fallback"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper kptr_xchg ptr expects pointer in [Kernel], got Context"
    }
    {
        name: "netfilter-state-context"
        category: "context-surface"
        tags: [netfilter context]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  ($ctx.hook + $ctx.pf + $ctx.protocol_family + $ctx.state.in.ifindex + $ctx.nf_state.out.ifindex + $ctx.skb.len) | count'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "netfilter-bound-state-context"
        category: "context-surface"
        tags: [netfilter context alias]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  let state = ($ctx.nf_state)'
            '  let skb = $ctx.skb'
            '  ($state.in.ifindex + $skb.len) | count'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "netfilter-bound-state-hop-context"
        category: "context-surface"
        tags: [netfilter context alias]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  let input = $ctx.state.in'
            '  ($input.ifindex + $ctx.hook) | count'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "netfilter-record-state-context"
        category: "context-surface"
        tags: [netfilter context record source metadata]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  let rec = { state: $ctx.nf_state skb: $ctx.skb }'
            '  ($rec.state.in.ifindex + $rec.skb.len + $ctx.hook) | count'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "netfilter-record-spread-state-context"
        category: "context-surface"
        tags: [netfilter context record spread source metadata]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  let base = { state: $ctx.state }'
            '  let rec = { ok: true, ...$base, skb: $ctx.skb }'
            '  ($rec.state.out.ifindex + $rec.skb.len + $ctx.pf) | count'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
]
