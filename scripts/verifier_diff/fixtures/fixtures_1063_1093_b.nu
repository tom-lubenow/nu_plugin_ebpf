const VERIFIER_DIFF_FIXTURES_1063_1093_B = [
    {
        name: "lirc-mode2-rc-helpers"
        category: "helper-state"
        tags: [lirc helper-call accept source metadata]
        target: "lirc_mode2:/dev/null"
        program: [
            '{|ctx|'
            '  helper-call "bpf_rc_repeat" $ctx'
            '  helper-call "bpf_rc_keydown" $ctx 0 0 0'
            '  helper-call "bpf_rc_pointer_rel" $ctx 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "raw-tracepoint-writable-args"
        category: "context-surface"
        tags: [raw-tracepoint-w context]
        target: "raw_tracepoint.w:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.arg0 + $ctx.arg1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-tracepoint-writable-current-context"
        category: "context-surface"
        tags: [raw-tracepoint-w context current]
        target: "raw_tracepoint.w:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.pid + $ctx.ktime + $ctx.cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
