const PROGRAM_SURFACE_TC_SOCKET_WRITE_KERNEL_FEATURE_EXPECTATIONS = [
    {
        target: "tc_action:demo"
        program: [
            '{|event|'
            '  $event.sk = 0'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_assign"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.sk = 0'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_assign"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  def passthrough [event] {'
            '    let actual = $event'
            '    $actual'
            '  }'
            '  mut event = (passthrough $ctx)'
            '  $event.sk = 0'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_assign"]
    }
]
