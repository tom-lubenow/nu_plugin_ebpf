const VERIFIER_DIFF_FIXTURES_2673_2681 = [
    {
        name: "core-control-flow-rejects-env-load"
        category: "language-core"
        tags: [control-flow env diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $env.PATH | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Environment variable access ($env.PATH) is not supported in eBPF. eBPF programs run in kernel space without access to the user environment."
    }
    {
        name: "core-control-flow-rejects-env-store"
        category: "language-core"
        tags: [control-flow env diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $env.NU_EBPF_TEST = "x"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Setting environment variable ($env.NU_EBPF_TEST) is not supported in eBPF. eBPF programs run in kernel space without access to the user environment."
    }
    {
        name: "core-control-flow-rejects-scalar-iteration"
        category: "language-core"
        tags: [control-flow loop diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  for i in $ctx.pid {'
            '    $i'
            '  }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Iterate requires a compile-time known range, bounded list, or fixed array"
    }
    {
        name: "core-list-spread-rejects-scalar-source"
        category: "language-core"
        tags: [aggregate list spread diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0 ...$ctx.pid] | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "fixed-layout list and array spread initializers require compile-time constant lists"
    }
    {
        name: "core-record-spread-rejects-scalar-source"
        category: "language-core"
        tags: [aggregate record spread diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { ok: true, ...$ctx.pid }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Record spread requires a source record with compiler-known fields in eBPF"
    }
    {
        name: "core-record-rejects-runtime-key"
        category: "language-core"
        tags: [aggregate record diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { ($ctx.comm): 1 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Record key must be a literal string"
    }
    {
        name: "core-seq-rejects-runtime-argument"
        category: "language-core"
        tags: [seq diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 1 $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq arguments must be compile-time known integers or floats in eBPF"
    }
    {
        name: "core-user-function-rejects-rest-parameters"
        category: "language-core"
        tags: [user-functions diagnostics reject rest]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def foo [...xs] { 0 }'
            '  foo 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "User-defined functions with rest parameters are not supported"
    }
    {
        name: "core-user-function-rejects-recursion"
        category: "language-core"
        tags: [user-functions diagnostics reject recursion]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def foo [] { foo }'
            '  foo'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Recursive user-defined functions are not supported in eBPF"
    }
]
