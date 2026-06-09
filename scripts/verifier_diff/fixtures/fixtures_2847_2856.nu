const VERIFIER_DIFF_FIXTURES_2847_2856 = [
    {
        name: "core-record-create-numeric-list-rejects-sparse-index"
        category: "path-diagnostics"
        tags: [records path diagnostics reject update list sparse]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  mut event = {}'
            '  $event.samples.1 = 7'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cell path update '.samples.1 = ...' can only create a missing list field at index 0"
    }
    {
        name: "core-record-create-numeric-list-rejects-string"
        category: "path-diagnostics"
        tags: [records path diagnostics reject update list type]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  mut event = {}'
            '  $event.labels.0 = "x"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cell path update '.labels.0 = ...' cannot create a numeric list from value type"
    }
    {
        name: "core-record-create-record-list-rejects-numeric-tail"
        category: "path-diagnostics"
        tags: [records path diagnostics reject update list nested]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  mut event = {}'
            '  $event.items.0.1 = 7'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cell path update '.items.0.1 = ...' can only synthesize list-of-record fields when the index is followed by a record field"
    }
    {
        name: "core-record-numeric-list-projection-rejects-capacity-index"
        category: "path-diagnostics"
        tags: [records path diagnostics reject get list bounds]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  let event = {samples: [1 2]}'
            '  $event.samples.2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "typed field path 'samples.2' index 2 is out of bounds for numeric list capacity 2"
    }
    {
        name: "core-scalar-cell-path-update-rejects-field-write"
        category: "path-diagnostics"
        tags: [path diagnostics reject update scalar]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  mut n = 1'
            '  $n.foo = 2'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cell path update '.foo = ...' requires a materialized stack/map aggregate pointer value"
    }
    {
        name: "core-record-numeric-list-update-rejects-string"
        category: "path-diagnostics"
        tags: [records path diagnostics reject update list type]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  mut event = {samples: [1]}'
            '  $event.samples.0 = "x"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cell path update '.samples.0 = ...' cannot store value type"
    }
    {
        name: "core-record-scalar-field-update-rejects-string"
        category: "path-diagnostics"
        tags: [records path diagnostics reject update field type]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  mut event = {pid: 1}'
            '  $event.pid = "x"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cell path update '.pid = ...' cannot store type"
    }
    {
        name: "core-record-aggregate-field-update-rejects-scalar"
        category: "path-diagnostics"
        tags: [records path diagnostics reject update aggregate type]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  mut event = {inner: {pid: 1}}'
            '  $event.inner = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cell path update '.inner = ...' requires a materialized aggregate pointer value for field"
    }
    {
        name: "kprobe-ancestor-cgroup-id-rejects-missing-level"
        category: "context-policy"
        tags: [kprobe context diagnostics reject cgroup path]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  $ctx.ancestor_cgroup_id'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.ancestor_cgroup_id requires a constant numeric ancestor level"
    }
    {
        name: "kprobe-ancestor-cgroup-id-rejects-negative-level"
        category: "context-policy"
        tags: [kprobe context diagnostics reject cgroup path bounds]
        target: "kprobe:vfs_read"
        program: [
            '{|ctx|'
            '  $ctx.ancestor_cgroup_id.-1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.ancestor_cgroup_id requires ancestor level 0..2147483647"
    }
]
