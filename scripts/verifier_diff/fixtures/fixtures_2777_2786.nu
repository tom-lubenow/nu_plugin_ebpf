const VERIFIER_DIFF_FIXTURES_2777_2786 = [
    {
        name: "core-record-update-rejects-missing-field"
        category: "records"
        tags: [records update diagnostics reject missing]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | update uid 2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "update cannot find record field 'uid'"
    }
    {
        name: "core-record-insert-rejects-non-record-input"
        category: "records"
        tags: [records insert diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | insert uid 2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "insert requires record input with compiler-known fields in eBPF"
    }
    {
        name: "core-record-update-rejects-non-record-input"
        category: "records"
        tags: [records update diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | update uid 2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "update requires record input with compiler-known fields in eBPF"
    }
    {
        name: "core-record-transpose-rejects-runtime-output-name"
        category: "records"
        tags: [records transpose diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | transpose $ctx.comm value'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "transpose requires compile-time field names in eBPF"
    }
    {
        name: "core-record-default-empty-rejects-runtime-empty-state"
        category: "records"
        tags: [records default empty diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | default --empty "fallback"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "default --empty requires compiler-known empty state in eBPF"
    }
    {
        name: "core-record-default-rejects-closure-value"
        category: "records"
        tags: [records default diagnostics reject closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  null | default {|| 1}'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "default closure values are not supported in eBPF"
    }
    {
        name: "core-record-insert-rejects-closure-replacement"
        category: "records"
        tags: [records insert diagnostics reject closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | insert uid {|| 2}'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "insert closure replacement values are not supported in eBPF"
    }
    {
        name: "core-record-update-rejects-closure-replacement"
        category: "records"
        tags: [records update diagnostics reject closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | update pid {|| 2}'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "update closure replacement values are not supported in eBPF"
    }
    {
        name: "core-record-upsert-rejects-closure-replacement"
        category: "records"
        tags: [records upsert diagnostics reject closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | upsert uid {|| 2}'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "upsert closure replacement values are not supported in eBPF"
    }
    {
        name: "core-record-select-rejects-nested-field-path"
        category: "records"
        tags: [records select diagnostics reject path]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | select pid.foo'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "select supports only top-level record field names in eBPF"
    }
]
