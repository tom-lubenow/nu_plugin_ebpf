[
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
]
