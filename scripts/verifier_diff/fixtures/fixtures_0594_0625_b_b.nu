const VERIFIER_DIFF_FIXTURES_0594_0625_B_B = [
    {
        name: "stackid-built-in-kstacks"
        category: "maps"
        tags: [helper-call stack-trace reserved-name]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_stackid" $ctx kstacks 0 | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "stackid-built-in-kstacks-rejects-dynamic-flags"
        category: "maps"
        tags: [helper-call stack-trace reserved-name flags reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_get_stackid" $ctx kstacks $flags | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_stackid' requires arg2 flags"
    }
    {
        name: "stackid-context-fields"
        category: "context-surface"
        tags: [context stack-trace kstack ustack accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ($ctx.kstack + $ctx.ustack) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "task-pt-regs-context"
        category: "context-surface"
        tags: [context task pt-regs helper-backed accept]
        requires: [kernel-btf]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.task.pt_regs.arg0 | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "task-pt-regs-bound-context"
        category: "context-surface"
        tags: [context task pt-regs helper-backed source metadata accept]
        requires: [kernel-btf]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let task = $ctx.task'
            '  $task.pt_regs.arg0 | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "helper-current-task-bound-projection"
        category: "context-surface"
        tags: [context task helper-call source metadata accept]
        requires: [kernel-btf]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let task = (helper-call "bpf_get_current_task_btf")'
            '  $task.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "current-cgroup-bound-context"
        category: "context-surface"
        tags: [context cgroup btf source metadata accept]
        requires: [kernel-btf]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let cg = $ctx.current_cgroup'
            '  $cg.kn.id | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-scalar-mut"
        category: "globals"
        tags: [data-global scalar]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut hits: int = 0'
            '  $hits = ($hits + 1)'
            '  $hits | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-cgroup-array-contains"
        category: "packet"
        tags: [tc-action cgroup-array helper-policy]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  map-contains tracked_cgroups 0 --kind cgroup-array'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-coarse-time-context"
        category: "context-surface"
        tags: [tc context time source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.ktime_coarse | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
