const VERIFIER_DIFF_FIXTURES_1063_1093_A_C = [
    {
        name: "lirc-mode2-context"
        category: "context-surface"
        tags: [lirc context]
        requires: [lirc-device]
        target: "lirc_mode2:/dev/lirc0"
        program: [
            '{|ctx|'
            '  ($ctx.sample + $ctx.value + $ctx.mode) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lirc-mode2-current-context"
        category: "context-surface"
        tags: [lirc context current]
        requires: [lirc-device]
        target: "lirc_mode2:/dev/lirc0"
        program: [
            '{|ctx|'
            '  ($ctx.cpu + $ctx.ktime + $ctx.cgroup_id) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
]
