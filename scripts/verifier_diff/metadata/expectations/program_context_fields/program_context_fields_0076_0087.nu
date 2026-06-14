[
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let base = { optval: $ctx.optval }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut rec = { optval: ($ctx | get optval) }'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert optval ($ctx | get optval))'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
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
        feature_keys: ["ctx:optval"]
    }
    {
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
        feature_keys: ["ctx:optval"]
    }
    {
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
        feature_keys: ["ctx:optval"]
    }
    {
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
        feature_keys: ["ctx:level" "ctx:optname" "ctx:optlen"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:getpeername4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.remote_ip4 = 2130706433'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:remote_ip4"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:getsockname6"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.local_ip6.1 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:local_ip6"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:sendmsg6"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.msg_src_ip6.3 = 42'
            '  $ctx.local_ip6.2 = 24'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:msg_src_ip6" "ctx:local_ip6"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let full = $ctx.sk.full'
            '  if $full { $full.family | count }'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_sk_fullsock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let listener = $ctx.sk.listener'
            '  if $listener { $listener.family | count }'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_get_listener_sock" "helper:bpf_probe_read_kernel"]
    }
]
