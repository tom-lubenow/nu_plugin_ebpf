const VERIFIER_DIFF_FIXTURES_2787_2796 = [
    {
        name: "core-record-select-rejects-missing-field-args"
        category: "records"
        tags: [records select diagnostics reject args]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | select'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "select requires at least one record field name in eBPF"
    }
    {
        name: "core-record-reject-rejects-missing-field-args"
        category: "records"
        tags: [records reject-cmd diagnostics reject args]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | reject'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "reject requires at least one record field name in eBPF"
    }
    {
        name: "core-record-reject-rejects-runtime-field-name"
        category: "records"
        tags: [records reject-cmd diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | reject $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "reject requires compile-time field names in eBPF"
    }
    {
        name: "core-record-reject-rejects-nested-field-path"
        category: "records"
        tags: [records reject-cmd diagnostics reject path]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | reject pid.foo'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "reject supports only top-level record field names in eBPF"
    }
    {
        name: "core-record-get-rejects-extra-field-args"
        category: "records"
        tags: [records get diagnostics reject args]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | get pid uid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "get accepts exactly one positional argument in eBPF"
    }
    {
        name: "core-record-get-rejects-runtime-field-name"
        category: "records"
        tags: [records get diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | get $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "get requires compile-time field names in eBPF"
    }
    {
        name: "core-record-get-rejects-nested-field-path"
        category: "records"
        tags: [records get diagnostics reject path]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | get pid.foo'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "get supports only top-level record field names in eBPF"
    }
    {
        name: "core-record-get-rejects-optional-flag"
        category: "records"
        tags: [records get diagnostics reject flag]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | get --optional pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "get does not accept named flags or arguments in eBPF"
    }
    {
        name: "core-record-select-rejects-optional-flag"
        category: "records"
        tags: [records select diagnostics reject flag]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | select --optional pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "select does not accept named flags or arguments in eBPF"
    }
    {
        name: "core-record-reject-rejects-optional-flag"
        category: "records"
        tags: [records reject-cmd diagnostics reject flag]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | reject --optional pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "reject does not accept named flags or arguments in eBPF"
    }
]
