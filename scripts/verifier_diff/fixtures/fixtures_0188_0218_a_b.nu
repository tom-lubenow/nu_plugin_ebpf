const VERIFIER_DIFF_FIXTURES_0188_0218_A_B = [
    {
        name: "fmod-ret-context"
        category: "tracing"
        tags: [fmod-ret context]
        requires: [kernel-btf]
        target: "fmod_ret:security_file_open"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg.file.f_flags + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fmod-ret-sleepable-context"
        category: "tracing"
        tags: [fmod-ret sleepable context]
        requires: [kernel-btf]
        target: "fmod_ret.s:security_file_open"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg.file.f_flags + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
