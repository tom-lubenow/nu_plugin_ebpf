const VERIFIER_DIFF_FIXTURES_0876_0906_B = [
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
]
