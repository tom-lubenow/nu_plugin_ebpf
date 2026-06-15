const VERIFIER_DIFF_FIXTURES_0438_0468_B_B = [
    {
        name: "source-helper-probe-read-accepts-kernel-src"
        category: "helper-state"
        tags: [helper probe-read accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "01234567"'
            '  helper-call "bpf_probe_read" $dst 8 $ctx.current_task'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-probe-read-str-accepts-kprobe-context"
        category: "helper-state"
        tags: [helper probe-read string accept source metadata]
        target: "kprobe:__x64_sys_getpid"
        program: [
            '{|ctx|'
            '  let dst = "01234567"'
            '  helper-call "bpf_probe_read_str" $dst 8 $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-probe-read-kernel-accepts-kernel-src"
        category: "helper-state"
        tags: [helper probe-read kernel accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "01234567"'
            '  helper-call "bpf_probe_read_kernel" $dst 8 $ctx.current_task'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-probe-read-kernel-str-accepts-kernel-src"
        category: "helper-state"
        tags: [helper probe-read kernel string accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "01234567"'
            '  helper-call "bpf_probe_read_kernel_str" $dst 8 $ctx.current_task'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-probe-read-user-accepts-user-src"
        category: "helper-state"
        tags: [helper probe-read user accept source metadata]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let dst = "01234567"'
            '    helper-call "bpf_probe_read_user" $dst 8 $ptr'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
