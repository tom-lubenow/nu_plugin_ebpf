let PROGRAM_SURFACE_TC_CONTEXT_WRITE_KERNEL_FEATURE_EXPECTATIONS = [
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let text = "$ctx.sk = 0; $ctx.sk == 0"'
            '  # $ctx.sk = 0'
            '  if $ctx.sk == 0 { 0 }'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|event|'
            '  assign-socket 0'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_sk_assign"]
    }
]
