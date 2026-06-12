[
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  def wrap [event] { { event: $event } }'
            '  mut rec = (wrap $ctx)'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:tstamp"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = (if $ctx.pid == 0 { 7 } else { 1 })'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:mark" "ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "lwt_xmit:demo-route"
        program: [
            '{|event|'
            '  mut event = $event'
            '  $event.mark = 7'
            '  $event.priority = 3'
            '  $event.cb.1 = 9'
            '  "reroute"'
            '}'
        ]
        feature_keys: ["ctx:mark" "ctx:priority" "ctx:cb"]
    }
    {
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let meta = $ctx.iter_meta'
            '  $meta.seq_num | count'
            '  if $ctx.iter_task { $ctx.iter_task.pid | count }'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:iter_meta" "ctx:iter_task" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "iter:task_file"
        program: [
            '{|ctx|'
            '  if $ctx.file { $ctx.file.f_mode | count }'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:iter_file" "helper:bpf_probe_read_kernel"]
    }
]
