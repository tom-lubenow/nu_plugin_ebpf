const VERIFIER_DIFF_FIXTURES_0876_1000 = [
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
    {
        name: "netfilter-user-function-record-state-context"
        category: "context-surface"
        tags: [netfilter context user-function record source metadata]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  def wrap [state] { { state: $state } }'
            '  let rec = (wrap $ctx.nf_state)'
            '  ($rec.state.in.ifindex + $ctx.skb.len + $ctx.protocol_family) | count'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "netfilter-rejects-flow-keys-context"
        category: "context-policy"
        tags: [netfilter reject context]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  $ctx.flow_keys.ip_proto | count'
            '  "accept"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.flow_keys is only available on flow_dissector programs"
    }
    {
        name: "netfilter-rejects-packet-context"
        category: "context-policy"
        tags: [netfilter reject context packet]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  $ctx.packet_len | count'
            '  "accept"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.packet_len is only available on packet-context programs"
    }
    {
        name: "cgroup-sockopt-retval-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.retval = 0'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-retval-alias-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut event = $ctx'
            '  $event.retval = 0'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-set-scalar-writes"
        category: "context-surface"
        tags: [cgroup-sockopt context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.level = 1'
            '  $ctx.optname = 2'
            '  $ctx.optlen = 4'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-set-scalar-alias-writes"
        category: "context-surface"
        tags: [cgroup-sockopt context writable alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  mut event = $ctx'
            '  $event.level = 1'
            '  $event.optname = 2'
            '  $event.optlen = 4'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-alias-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut event = $ctx'
            '  $event.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-bound-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut optval = $ctx.optval'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-bound-get-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable alias get source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut optval = ($ctx | get optval)'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-user-function-returned-context-root-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable user-function alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def get_optval [event] { $event.optval }'
            '  mut optval = (get_optval $ctx)'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-user-function-returned-get-context-root-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable user-function alias get source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def get_optval [event] { $event | get optval }'
            '  mut optval = (get_optval $ctx)'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-record-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable record source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut rec = { optval: $ctx.optval }'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-record-get-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable record get source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut rec = { optval: ($ctx | get optval) }'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-record-pipeline-upsert-get-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable record pipeline upsert get source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert optval ($ctx | get optval))'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-record-spread-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable record spread source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let base = { optval: $ctx.optval }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-user-function-record-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable user-function record source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] { { optval: $optval } }'
            '  let optval = $ctx.optval'
            '  mut rec = (wrap $optval)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-user-function-record-direct-spread-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable user-function record spread source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] {'
            '    let base = { optval: $optval }'
            '    { ok: true, ...$base }'
            '  }'
            '  let optval = $ctx.optval'
            '  mut rec = (wrap $optval)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-nested-user-function-record-spread-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable user-function record spread nested source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] { { optval: $optval } }'
            '  def outer [event] {'
            '    let optval = $event.optval'
            '    let base = (wrap $optval)'
            '    { ok: true, ...$base }'
            '  }'
            '  mut rec = (outer $ctx)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-getsockopt-cgroup-sockopt"
        category: "helper-state"
        tags: [helper-call cgroup-sockopt socket-option source accept]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let optval = "01234567"'
            '  helper-call "bpf_getsockopt" $ctx 1 2 $optval 8'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-setsockopt-cgroup-sockopt"
        category: "helper-state"
        tags: [helper-call cgroup-sockopt socket-option source accept]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  let optval = "01234567"'
            '  helper-call "bpf_setsockopt" $ctx 1 2 $optval 8'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-getsockopt-rejects-non-socket-option-context"
        category: "helper-state"
        tags: [helper-call cgroup-sockopt socket-option source reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let optval = "01234567"'
            '  helper-call "bpf_getsockopt" $ctx 1 2 $optval 8'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_getsockopt' is only valid in sock_ops, cgroup_sock_addr, and cgroup_sockopt programs"
    }
    {
        name: "source-helper-get-retval-cgroup-device"
        category: "helper-state"
        tags: [helper-call cgroup-retval source accept]
        requires: [cgroup-v2]
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_retval" | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-set-retval-cgroup-sock"
        category: "helper-state"
        tags: [helper-call cgroup-retval cgroup-sock source accept]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:sock_create"
        program: [
            '{|ctx|'
            '  helper-call "bpf_set_retval" (-1)'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-retval-cgroup-sockopt"
        category: "helper-state"
        tags: [helper-call cgroup-retval cgroup-sockopt source accept]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_retval" | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-set-retval-cgroup-sock-addr-sendmsg"
        category: "helper-state"
        tags: [helper-call cgroup-retval cgroup-sock-addr source accept]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:sendmsg4"
        program: [
            '{|ctx|'
            '  helper-call "bpf_set_retval" (-1)'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-retval-cgroup-sysctl"
        category: "helper-state"
        tags: [helper-call cgroup-retval cgroup-sysctl source accept]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_retval" | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-retval-rejects-non-cgroup-context"
        category: "helper-state"
        tags: [helper-call cgroup-retval source reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_retval" | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_retval' is only valid in cgroup_device, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, and cgroup_sysctl programs"
    }
    {
        name: "source-helper-set-retval-rejects-cgroup-sock-addr-getpeername"
        category: "helper-state"
        tags: [helper-call cgroup-retval cgroup-sock-addr source reject]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:getpeername4"
        program: [
            '{|ctx|'
            '  helper-call "bpf_set_retval" (-1)'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_set_retval' is not valid on cgroup_sock_addr recvmsg/getpeername/getsockname hooks"
    }
    {
        name: "cgroup-sockopt-get-context-fields"
        category: "context-surface"
        tags: [cgroup-sockopt context source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  ($ctx.level + $ctx.optname + $ctx.optlen + $ctx.retval + $ctx.netns_cookie) | count'
            '  if $ctx.optval { 1 | count }'
            '  if $ctx.optval_end { 1 | count }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-get-optlen-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optlen = 4'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-get-rejects-level-write"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.level = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.level is only writable on cgroup_sockopt:set hooks"
    }
    {
        name: "cgroup-sockopt-get-rejects-optname-write"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optname = 2'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.optname is only writable on cgroup_sockopt:set hooks"
    }
    {
        name: "cgroup-sockopt-rejects-optval-write-without-index"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optval = 42'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a fixed index"
    }
    {
        name: "cgroup-sockopt-set-rejects-retval-write"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.retval = 0'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cgroup_sockopt:get"
    }
    {
        name: "cgroup-sockopt-set-rejects-retval-read"
        category: "context-policy"
        tags: [cgroup-sockopt reject context]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  $ctx.retval | count'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cgroup_sockopt:get"
    }
    {
        name: "cgroup-sockopt-rejects-optval-write-on-packet-context"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optval.0 = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.optval is only available on cgroup_sockopt programs"
    }
    {
        name: "cgroup-sockopt-bound-tcp-socket-projection"
        category: "context-surface"
        tags: [cgroup-sockopt context source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  $sk.tcp.snd_cwnd | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-bound-parenthesized-tcp-socket-projection"
        category: "context-surface"
        tags: [cgroup-sockopt context alias parenthesized source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = ($ctx.sk)'
            '  $sk.tcp.snd_cwnd | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-socket-helper-root-alias-context"
        category: "context-surface"
        tags: [cgroup-sockopt context socket alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.socket.tcp'
            '  if $tcp {'
            '    $tcp.snd_cwnd | count'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-bound-tcp-helper-pointer"
        category: "context-surface"
        tags: [cgroup-sockopt context alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.sk.tcp'
            '  if $tcp {'
            '    $tcp.snd_cwnd | count'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-record-bound-tcp-helper-pointer"
        category: "context-surface"
        tags: [cgroup-sockopt context record alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.sk.tcp'
            '  let rec = { tcp: $tcp }'
            '  if $rec.tcp {'
            '    $rec.tcp.snd_cwnd | count'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-bound-full-helper-pointer"
        category: "context-surface"
        tags: [tc context alias source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let full = $ctx.sk.full'
            '  if $full {'
            '    $full.family | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-returned-context-root-projection"
        category: "context-surface"
        tags: [tc context user-function alias source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_sk [event] { $event.sk }'
            '  let sk = (get_sk $ctx)'
            '  $sk.family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-context-root-projection"
        category: "context-surface"
        tags: [tc context record source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { root: $ctx socket: $ctx.sk }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-bound-context-root-projection"
        category: "context-surface"
        tags: [tc context record alias source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  let rec = { socket: $sk }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-skb-bound-listener-helper-pointer"
        category: "context-surface"
        tags: [cgroup-skb context alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let listener = $ctx.sk.listener'
            '  if $listener {'
            '    $listener.family | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-skb-socket-helper-root-alias-context"
        category: "context-surface"
        tags: [cgroup-skb context socket alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let listener = $ctx.sock.listener'
            '  let full = $ctx.socket.full'
            '  if $listener {'
            '    $listener.family | count'
            '  }'
            '  if $full {'
            '    $full.family | count'
            '  }'
            '  ($ctx.sock.cgroup_id + $ctx.socket.ancestor_cgroup_id.0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-device-context"
        category: "context-surface"
        tags: [cgroup-device context]
        requires: [cgroup-v2]
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.access_type + $ctx.device_access + $ctx.device_type + $ctx.major + $ctx.minor) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-device-current-context"
        category: "context-surface"
        tags: [cgroup-device context current]
        requires: [cgroup-v2]
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.cpu + $ctx.ktime + $ctx.cgroup_id) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-device-rejects-packet-context"
        category: "context-policy"
        tags: [cgroup-device reject context]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.access_type | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.access_type is only available on cgroup_device programs"
    }
    {
        name: "cgroup-device-rejects-major-write"
        category: "context-policy"
        tags: [cgroup-device reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.major = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.major is read-only"
    }
    {
        name: "cgroup-sysctl-new-value-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.file_pos = 0'
            '  $ctx.new_value = "1"'
            '  $ctx.name | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-new-value-alias-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable alias]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = $ctx'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-new-value-record-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable record source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.new_value = "1"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-base-name-context"
        category: "context-surface"
        tags: [cgroup-sysctl context helper-backed alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.write + $ctx.file_pos) | count'
            '  $ctx.base_name | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-new-value-parenthesized-alias-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable alias parenthesized source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = ($ctx)'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-user-function-returned-context-new-value-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable user-function alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def get_event [event] { $event }'
            '  mut writable = (get_event $ctx)'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-current-value-context"
        category: "context-surface"
        tags: [cgroup-sysctl context helper-backed]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx.current_value | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-new-value-context"
        category: "context-surface"
        tags: [cgroup-sysctl context helper-backed]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx.new_value | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-new-value-parenthesized-alias-read"
        category: "context-surface"
        tags: [cgroup-sysctl context helper-backed alias parenthesized source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let readable = ($ctx)'
            '  $readable.new_value | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-rejects-write-field-write"
        category: "context-policy"
        tags: [cgroup-sysctl reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.write = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.write is read-only"
    }
    {
        name: "cgroup-sysctl-rejects-new-value-index-write"
        category: "context-policy"
        tags: [cgroup-sysctl reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.new_value.0 = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.new_value does not support indexed assignment"
    }
    {
        name: "cgroup-sysctl-rejects-file-pos-on-packet-context"
        category: "context-policy"
        tags: [cgroup-sysctl reject context]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.file_pos | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.file_pos is only available on cgroup_sysctl programs"
    }
    {
        name: "sock-ops-basic-context-write"
        category: "context-surface"
        tags: [sock-ops context writable]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.op + ($ctx.args | get 0) + $ctx.reply + ($ctx.replylong | get 0) + $ctx.family + $ctx.remote_port + $ctx.socket_cookie + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.reply = 1'
            '  $ctx.replylong.0 = 7'
            '  $ctx.cb_flags = 1'
            '  $ctx.sk_txhash = 7'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-cb-flags-helper-backed-write"
        category: "context-surface"
        tags: [sock-ops context writable source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.cb_flags = 1'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-cb-flags-record-helper-backed-write"
        category: "context-surface"
        tags: [sock-ops context writable record source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.cb_flags = 1'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-cb-flags-user-function-returned-context-write"
        category: "context-surface"
        tags: [sock-ops context writable user-function alias source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def get_event [event] { $event }'
            '  mut writable = (get_event $ctx)'
            '  $writable.cb_flags = 1'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-metrics-context"
        category: "context-surface"
        tags: [sock-ops context source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.is_fullsock + $ctx.snd_cwnd + $ctx.srtt_us + $ctx.state + $ctx.rtt_min + $ctx.snd_ssthresh + $ctx.rcv_nxt + $ctx.snd_nxt) | count'
            '  ($ctx.snd_una + $ctx.mss_cache + $ctx.ecn_flags + $ctx.rate_delivered + $ctx.rate_interval_us + $ctx.packets_out + $ctx.retrans_out + $ctx.total_retrans) | count'
            '  ($ctx.segs_in + $ctx.data_segs_in + $ctx.segs_out + $ctx.data_segs_out + $ctx.lost_out + $ctx.sacked_out + ($ctx.bytes_received mod 1024) + ($ctx.bytes_acked mod 1024)) | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-rejects-replylong-write-without-index"
        category: "context-policy"
        tags: [sock-ops reject context writable]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.replylong = 7'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a fixed index"
    }
    {
        name: "sock-ops-rejects-reply-write-on-packet-context"
        category: "context-policy"
        tags: [sock-ops reject context writable]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.reply = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sock_ops programs"
    }
    {
        name: "sock-ops-rejects-cb-flags-write-on-packet-context"
        category: "context-policy"
        tags: [sock-ops reject context writable]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.cb_flags = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sock_ops programs"
    }
    {
        name: "sock-ops-rejects-sk-txhash-write-on-packet-context"
        category: "context-policy"
        tags: [sock-ops reject context writable]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk_txhash = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sock_ops programs"
    }
    {
        name: "sock-ops-bound-socket-projection-context"
        category: "context-surface"
        tags: [sock-ops context source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  $sk.rx_queue_mapping | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-bound-socket-parenthesized-projection-context"
        category: "context-surface"
        tags: [sock-ops context alias parenthesized source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let sk = ($ctx.sk)'
            '  $sk.rx_queue_mapping | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-socket-root-alias-context"
        category: "context-surface"
        tags: [sock-ops context socket alias source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let sock = $ctx.sock'
            '  ($sock.rx_queue_mapping + $ctx.socket.state) | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-enable-tx-tstamp-kfunc"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source metadata]
        requires: [cgroup-v2 kernel-btf]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_sock_ops_enable_tx_tstamp" $ctx 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-enable-tx-tstamp-copied-raw-context"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source metadata context-alias]
        requires: [cgroup-v2 kernel-btf]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let raw_ctx = $ctx'
            '  kfunc-call "bpf_sock_ops_enable_tx_tstamp" $raw_ctx 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-enable-tx-tstamp-user-function-raw-context"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source metadata user-function]
        requires: [cgroup-v2 kernel-btf]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def enable [raw_ctx] {'
            '    kfunc-call "bpf_sock_ops_enable_tx_tstamp" $raw_ctx 0'
            '    0'
            '  }'
            '  enable $ctx'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-enable-tx-tstamp-returned-raw-context"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source metadata user-function]
        requires: [cgroup-v2 kernel-btf]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def get_ctx [event] { $event }'
            '  let raw_ctx = (get_ctx $ctx)'
            '  kfunc-call "bpf_sock_ops_enable_tx_tstamp" $raw_ctx 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-enable-tx-tstamp-rejects-socket-arg"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source reject]
        requires: [cgroup-v2 kernel-btf]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_sock_ops_enable_tx_tstamp" $ctx.sk 0'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_sock_ops_enable_tx_tstamp' arg0 expects bpf_sock_ops pointer"
    }
    {
        name: "sock-ops-enable-tx-tstamp-rejects-non-sock-ops"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_sock_ops_enable_tx_tstamp" $ctx 0'
            '  2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_sock_ops_enable_tx_tstamp' is only valid in sock_ops programs"
    }
    {
        name: "sock-ops-hdr-opt-helpers"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let opt = "0123456789abcdef"'
            '  helper-call "bpf_load_hdr_opt" $ctx $opt 16 0'
            '  helper-call "bpf_store_hdr_opt" $ctx $opt 16 0'
            '  helper-call "bpf_reserve_hdr_opt" $ctx 16 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-load-hdr-opt-rejects-dynamic-flags"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let opt = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_load_hdr_opt" $ctx $opt 16 $flags'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_load_hdr_opt' requires arg3 flags"
    }
    {
        name: "sock-ops-store-hdr-opt-rejects-dynamic-flags"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  if ($ctx.op == 15) {'
            '    let opt = "0123456789abcdef"'
            '    let flags = (helper-call "bpf_get_prandom_u32")'
            '    helper-call "bpf_store_hdr_opt" $ctx $opt 16 $flags'
            '  }'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_store_hdr_opt' requires arg3 = 0"
    }
    {
        name: "sock-ops-reserve-hdr-opt-rejects-dynamic-flags"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_reserve_hdr_opt" $ctx 16 $flags'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_reserve_hdr_opt' requires arg2 = 0"
    }
    {
        name: "sock-ops-sock-map-update-helper"
        category: "helper-state"
        tags: [sock-ops helper-call sockmap accept source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  helper-call "bpf_sock_map_update" $ctx peers $key 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-sock-hash-update-helper"
        category: "helper-state"
        tags: [sock-ops helper-call sockhash accept source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  helper-call "bpf_sock_hash_update" $ctx hash_peers $key 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-sock-map-update-rejects-invalid-flags"
        category: "helper-state"
        tags: [sock-ops helper-call sockmap flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  helper-call "bpf_sock_map_update" $ctx peers $key 4'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "socket map update helpers require arg3 flags"
    }
    {
        name: "sock-ops-sock-map-update-rejects-dynamic-flags"
        category: "helper-state"
        tags: [sock-ops helper-call sockmap flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_sock_map_update" $ctx peers $key $flags'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "socket map update helpers require arg3 flags"
    }
    {
        name: "sock-ops-sock-hash-update-rejects-dynamic-flags"
        category: "helper-state"
        tags: [sock-ops helper-call sockhash flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_sock_hash_update" $ctx hash_peers $key $flags'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "socket map update helpers require arg3 flags"
    }
    {
        name: "sock-ops-sock-map-update-rejects-non-sock-ops"
        category: "helper-state"
        tags: [sock-ops helper-call sockmap program-policy reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  helper-call "bpf_sock_map_update" $ctx peers $key 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sock_map_update' is only valid in sock_ops programs"
    }
    {
        name: "sock-ops-store-hdr-opt-rejects-stale-data"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt packet-bounds reject]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  if ($ctx.op == 15) {'
            '    let data = $ctx.data'
            '    let opt = "0123456789abcdef"'
            '    helper-call "bpf_store_hdr_opt" $ctx $opt 16 0'
            '    ($data | get 0) | count'
            '  }'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "sock-ops-store-hdr-opt-allows-reloaded-data"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt packet-bounds accept]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  if ($ctx.op == 15) {'
            '    let opt = "0123456789abcdef"'
            '    helper-call "bpf_store_hdr_opt" $ctx $opt 16 0'
            '    ($ctx.data | get 0) | count'
            '  }'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-packet-metadata-requires-op-guard"
        category: "context-policy"
        tags: [sock-ops context packet reject]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.skb_len + $ctx.skb_tcp_flags) | count'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.packet_len on sock_ops requires proving a packet-aware ctx.op callback before use"
    }
    {
        name: "sock-ops-packet-metadata-op-guard"
        category: "context-surface"
        tags: [sock-ops context packet accept]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  if ($ctx.op == 13) {'
            '    ($ctx.packet_len + $ctx.skb_len + $ctx.skb_tcp_flags) | count'
            '  }'
            '  if ($ctx.op == 16) {'
            '    ($ctx.packet_len + $ctx.skb_len + ($ctx.skb_hwtstamp mod 1024)) | count'
            '  }'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-packet-data-requires-op-guard"
        category: "context-policy"
        tags: [sock-ops context packet reject]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.data | get 0) | count'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.data on sock_ops requires proving a packet-aware ctx.op callback before use"
    }
    {
        name: "sock-ops-packet-data-op-guard"
        category: "context-surface"
        tags: [sock-ops context packet accept]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  if ($ctx.op == 13) {'
            '    if ($ctx.data_end != 0) {'
            '      ($ctx.data | get 0) | count'
            '    }'
            '  }'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-select-context"
        category: "context-surface"
        tags: [sk-reuseport context]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  ($ctx.hash + $ctx.socket_cookie + $ctx.sk.family) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-select-packet-context"
        category: "context-surface"
        tags: [sk-reuseport context packet]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  (($ctx.data | get 0) + $ctx.packet_len + $ctx.sk.bound_dev_if) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-select-rich-context"
        category: "context-surface"
        tags: [sk-reuseport context packet socket source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  (($ctx.data | get 0) + $ctx.packet_len + $ctx.eth_protocol + $ctx.protocol + $ctx.hash + $ctx.bind_inany + $ctx.socket_cookie) | count'
            '  ($ctx.sk.family + $ctx.sk.type + $ctx.sk.protocol + $ctx.sk.mark + $ctx.sk.priority + $ctx.sk.rx_queue_mapping) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-socket-root-alias-context"
        category: "context-surface"
        tags: [sk-reuseport context socket alias source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  ($ctx.sock.family + $ctx.socket.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-record-socket-context"
        category: "context-surface"
        tags: [sk-reuseport context socket record source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  let rec = { sock: $ctx.sk }'
            '  ($rec.sock.family + $ctx.hash) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-record-spread-socket-context"
        category: "context-surface"
        tags: [sk-reuseport context socket record spread source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  let base = { sock: $ctx.sock }'
            '  let rec = { ok: true, ...$base }'
            '  ($rec.sock.priority + $ctx.protocol) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-user-function-record-socket-context"
        category: "context-surface"
        tags: [sk-reuseport context socket user-function record source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  def wrap [sock] { { sock: $sock } }'
            '  let rec = (wrap $ctx.sk)'
            '  ($rec.sock.rx_queue_mapping + $ctx.bind_inany) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-migrate-context"
        category: "context-surface"
        tags: [sk-reuseport context]
        target: "sk_reuseport:migrate"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.protocol + $ctx.hash + $ctx.bind_inany + $ctx.socket_cookie + $ctx.sk.bound_dev_if + $ctx.migrating_sk.bound_dev_if) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-migrating-socket-alias-context"
        category: "context-surface"
        tags: [sk-reuseport context socket alias source metadata]
        target: "sk_reuseport:migrate"
        program: [
            '{|ctx|'
            '  let migrating = $ctx.migrating_socket'
            '  if $migrating {'
            '    $migrating.remote_port | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-record-migrating-socket-context"
        category: "context-surface"
        tags: [sk-reuseport context socket record source metadata]
        target: "sk_reuseport:migrate"
        program: [
            '{|ctx|'
            '  let rec = { migrating: $ctx.migrating_socket }'
            '  if $rec.migrating {'
            '    $rec.migrating.remote_port | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-select-migrating-sk-nullable-context"
        category: "context-surface"
        tags: [sk-reuseport context socket source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  if $ctx.migrating_sk {'
            '    $ctx.migrating_sk.family | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
