const VERIFIER_DIFF_FIXTURES_2767_2776 = [
    {
        name: "core-record-rename-rejects-column-and-block"
        category: "records"
        tags: [records rename column block diagnostics reject conflict]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | rename --column {pid: uid} --block {|x| str upcase }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "rename --block cannot be combined with --column in eBPF"
    }
    {
        name: "core-record-rename-rejects-block-and-positional"
        category: "records"
        tags: [records rename block positional diagnostics reject conflict]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | rename uid --block {|x| str upcase }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "rename --block cannot be combined with positional field names in eBPF"
    }
    {
        name: "core-record-rename-rejects-column-and-positional"
        category: "records"
        tags: [records rename column positional diagnostics reject conflict]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | rename uid --column {pid: uid}'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "rename --column cannot be combined with positional field names in eBPF"
    }
    {
        name: "core-record-rename-column-rejects-missing-field"
        category: "records"
        tags: [records rename column diagnostics reject missing]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | rename --column {uid: gid}'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "rename --column cannot find record field 'uid'"
    }
    {
        name: "core-record-rename-column-rejects-non-string-target"
        category: "records"
        tags: [records rename column diagnostics reject target]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | rename --column {pid: 1}'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "rename --column requires compile-time string replacement field names in eBPF"
    }
    {
        name: "core-record-rename-block-rejects-empty-transform"
        category: "records"
        tags: [records rename block diagnostics reject empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | rename --block {|x| }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "rename --block requires at least one string transform command in eBPF"
    }
    {
        name: "core-record-rename-block-rejects-unknown-transform"
        category: "records"
        tags: [records rename block diagnostics reject transform]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | rename --block {|x| str length }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "rename --block supports only known string transform commands in eBPF, got 'str length'"
    }
    {
        name: "core-record-transpose-rejects-runtime-record-values"
        category: "records"
        tags: [records transpose diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | transpose'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "transpose requires compile-time known record values in eBPF"
    }
    {
        name: "core-record-default-rejects-missing-input"
        category: "records"
        tags: [records default diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  default 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "default requires pipeline input in eBPF"
    }
    {
        name: "core-record-insert-rejects-existing-field"
        category: "records"
        tags: [records insert diagnostics reject existing]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | insert pid 2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "insert cannot replace existing record field 'pid'"
    }
]
