[
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let docs = "$ctx.pid $ctx.sk.family"'
            '  # $ctx.pid $ctx.sk.family'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  let rec = { root: $ctx }'
            '  let docs = "$sk.family $rec.root.sk.family"'
            '  # $sk.family $rec.root.sk.family'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: $ctx.sk }'
            '  let sk = ($rec | get socket)'
            '  $sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: $ctx.sk }'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { ok: true, socket: $ctx.sk }'
            '  $rec | rename keep sock | get sock | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [sock] { { socket: $sock } }'
            '  wrap $ctx.sk | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | insert socket ($ctx | get sk))'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "ctx:family" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ socket: ($ctx | get sk) } | rename sock)'
            '  $rec | get sock | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "ctx:family" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | merge { socket: ($ctx | get sk) })'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "ctx:family" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | default ($ctx | get sk) socket)'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "ctx:family" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ socket: $ctx.sk } | update socket ($ctx | get sk))'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "ctx:family" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get packet_len | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:packet_len"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get data | get 0 | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get sk | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = ($ctx | get sk)'
            '  $sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: ($ctx | get sk) }'
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
            '  def get_sk [c] { $c | get sk }'
            '  let sk = (get_sk $ctx)'
            '  $sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [c] { { socket: ($c | get sk) } }'
            '  wrap $ctx | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def read_packet [event] {'
            '    $event | get packet_len | count'
            '    0'
            '  }'
            '  read_packet $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:packet_len"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def read_family [event] {'
            '    let sk = ($event | get sk)'
            '    $sk | get family | count'
            '    0'
            '  }'
            '  read_family $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx| $ctx | get sk | get family | count; 0}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|event|'
            '  $event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  let event = (id $ctx)'
            '  $event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def id [x] { ($x) }'
            '  let event = (id ($ctx))'
            '  $event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
]
