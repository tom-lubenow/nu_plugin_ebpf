const VERIFIER_DIFF_FIXTURES_2662_2672 = [
    {
        name: "core-record-rename-rejects-non-record-input"
        category: "records"
        tags: [records rename diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | rename uid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "rename requires record input with compiler-known fields in eBPF"
    }
    {
        name: "core-record-rename-column-rejects-empty-mapping"
        category: "records"
        tags: [records rename column diagnostics reject empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | rename --column {}'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "rename --column requires a non-empty record mapping in eBPF"
    }
    {
        name: "core-record-rename-column-rejects-runtime-mapping"
        category: "records"
        tags: [records rename column diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | rename --column {pid: $ctx.comm}'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "rename --column requires a compile-time record mapping in eBPF"
    }
    {
        name: "core-record-rename-block-rejects-unsupported-closure"
        category: "records"
        tags: [records rename block diagnostics reject closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | rename --block {|x| $x | str upcase "extra" }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "rename --block supports only a straight-line string transform closure in eBPF"
    }
    {
        name: "core-record-merge-rejects-non-record-input"
        category: "records"
        tags: [records merge diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | merge {uid: 1}'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "merge requires record input with compiler-known fields in eBPF"
    }
    {
        name: "core-record-values-rejects-non-record-input"
        category: "records"
        tags: [records values diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | values'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "values requires record input with compiler-known fields in eBPF"
    }
    {
        name: "core-record-columns-rejects-non-record-input"
        category: "records"
        tags: [records columns diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | columns'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "columns requires record input with compiler-known fields in eBPF"
    }
    {
        name: "core-record-select-rejects-runtime-field-name"
        category: "records"
        tags: [records select diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | select $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "select requires compile-time field names in eBPF"
    }
    {
        name: "core-record-default-column-rejects-non-record-input"
        category: "records"
        tags: [records default diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | default 7 uid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "default column fill requires record input with compiler-known fields in eBPF"
    }
    {
        name: "core-record-upsert-rejects-non-record-input"
        category: "records"
        tags: [records upsert diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | upsert uid 2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "upsert requires record input with compiler-known fields in eBPF"
    }
    {
        name: "core-record-get-rejects-scalar-input"
        category: "records"
        tags: [records get diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | get uid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "get FIELD requires record, context, or typed pointer input in eBPF, got U32"
    }
]
