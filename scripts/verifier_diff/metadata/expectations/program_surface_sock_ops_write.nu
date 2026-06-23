const PROGRAM_SURFACE_SOCK_OPS_WRITE_KERNEL_FEATURE_EXPECTATIONS = [
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|event|'
            '  $event.cb_flags = 1'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sock_ops_cb_flags_set"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.cb_flags = 1'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sock_ops_cb_flags_set"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def passthrough [event] {'
            '    let actual = $event'
            '    $actual'
            '  }'
            '  mut event = (passthrough $ctx)'
            '  $event.cb_flags = 1'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sock_ops_cb_flags_set"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  1 | map-put peers 0 --kind sockmap; 1 | map-put hash_peers 0 --kind sockhash'
            '  1'
            '}'
        ]
        feature_keys: [
            "helper:bpf_sock_map_update"
            "helper:bpf_sock_hash_update"
        ]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|event|'
            '  let text = "$event.cb_flags = 1"'
            '  # $event.cb_flags = 1'
            '  if $event.cb_flags == 1 { 0 }'
            '  1'
            '}'
        ]
        feature_keys: []
    }
]
