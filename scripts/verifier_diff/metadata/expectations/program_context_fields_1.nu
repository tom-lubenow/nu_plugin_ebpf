const PROGRAM_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS_1 = [
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
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def read_pid [event] {'
            '    $event.pid | count'
            '    0'
            '  }'
            '  let seen = (read_pid $ctx)'
            '  $seen | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def passthrough [event] {'
            '    let actual = $event'
            '    $actual'
            '  }'
            '  let event = (passthrough $ctx)'
            '  $event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "kretprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.retval | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:retval"]
    }
    {
        target: "fexit:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.retval | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:retval"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = { event: $ctx }'
            '  $rec.event.pid | count'
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
            '  let rec = { event: (id $ctx) }'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|event| let rec = { event: $event }; $rec.event.pid | count }'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|event| let base = { event: $event }; let rec = { ok: true, ...$base }; $rec.event.pid | count }'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let base = { event: $ctx }'
            '  let rec = { ok: true, ...$base }'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut rec = { event: null }'
            '  $rec.event = $ctx'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.event = $ctx'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def wrap [event] { { event: $event } }'
            '  let rec = (wrap $ctx)'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def wrap [event] {'
            '    mut rec = { event: null }'
            '    $rec.event = $event'
            '    $rec'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def wrap [event] {'
            '    mut rec = {}'
            '    $rec.event = $event'
            '    $rec'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def wrap [event] {'
            '    let base = { event: $event }'
            '    let rec = { ok: true, ...$base }'
            '    $rec'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def wrap [event] {'
            '    let base = { event: $event }'
            '    { ok: true, ...$base }'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def read_pid [c] {'
            '    $c.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  def read_pid [c] {'
            '    let actual = (id $c)'
            '    $actual.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  def id2 [x] { id $x }'
            '  def read_pid [c] {'
            '    let actual = (id2 $c)'
            '    $actual.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  def id2 [x] { id ($x) }'
            '  def read_pid [c] {'
            '    let actual = (id2 $c)'
            '    $actual.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint.w:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.pid + $ctx.ktime) | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "ctx:timestamp" "helper:bpf_get_current_pid_tgid" "helper:bpf_ktime_get_ns"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  $sk.rx_queue_mapping | count'
            '  1'
            '}'
        ]
        feature_keys: ["ctx:rx_queue_mapping" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = ($ctx.sk)'
            '  $sk.tcp.snd_cwnd | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  let sk = (id $ctx.sk)'
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
            '  def id [x] { $x }'
            '  let sk = $ctx.sk'
            '  let same = (id $sk)'
            '  $same.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_sk [event] { $event.sk }'
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
            '  def wrap [ignored event] { { socket: ($event | get sk) } }'
            '  let rec = (wrap 0 $ctx)'
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
            '  def read_family [sk] {'
            '    $sk.family | count'
            '    0'
            '  }'
            '  let sk = $ctx.sk'
            '  let seen = (read_family $sk)'
            '  $seen | count'
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
            '  def id [x] { $x }'
            '  let rec = { socket: (id $ctx.sk) }'
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
            '  let rec = { socket: ($ctx.sk) }'
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
            '  let rec = { root: $ctx socket: $ctx.sk }'
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
            '  let sk = $ctx.sk'
            '  let rec = { socket: $sk }'
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
            '  def wrap_socket [sock] { { socket: $sock } }'
            '  def wrap_event [event] {'
            '    let sock = $event.sk'
            '    let base = (wrap_socket $sock)'
            '    { ok: true, ...$base }'
            '  }'
            '  let rec = (wrap_event $ctx)'
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
            '  let inserted = ({ ok: true } | insert socket $ctx.sk)'
            '  let base = { socket: null }'
            '  let updated = ($base | update socket $ctx.sk)'
            '  let upserted = ({ ok: true } | upsert socket $ctx.sk)'
            '  $inserted.socket.family | count'
            '  $updated.socket.family | count'
            '  $upserted.socket.family | count'
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
            '  let rec = ($base | upsert ok true)'
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
]
