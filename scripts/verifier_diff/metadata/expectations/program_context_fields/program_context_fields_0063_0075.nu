[
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ socket: $ctx.sk, keep: 1 } | merge { ok: true } | select socket ok | reject ok | rename sock)'
            '  $rec.sock.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | default $ctx.sk socket)'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let base = { socket: $ctx.sk }'
            '  let rec = ({ ...$base } | rename sock)'
            '  $rec.sock.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [sock] { { ok: true } | upsert socket $sock }'
            '  let rec = (wrap $ctx.sk)'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  $sk.tcp.snd_cwnd | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.socket.tcp'
            '  if $tcp { $tcp.snd_cwnd | count }'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.sk.tcp'
            '  if $tcp { $tcp.snd_cwnd | count }'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.sk.tcp'
            '  let rec = { tcp: $tcp }'
            '  if $rec.tcp { $rec.tcp.snd_cwnd | count }'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.retval = 0'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sockopt_retval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut optval = $ctx.optval'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut optval = ($ctx | get optval)'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def get_optval [event] { $event | get optval }'
            '  mut optval = (get_optval $ctx)'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
]
