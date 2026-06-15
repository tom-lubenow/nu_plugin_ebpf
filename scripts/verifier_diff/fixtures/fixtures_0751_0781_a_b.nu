const VERIFIER_DIFF_FIXTURES_0751_0781_A_B = [
    {
        name: "helper-get-stack-rejects-task-ctx-arg"
        category: "helper-state"
        tags: [helper raw-context reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define scratch --kind array --value-type bytes:8 --max-entries 1'
            '  let dst = (0 | map-get scratch --kind array)'
            '  let task = (helper-call "bpf_get_current_task_btf")'
            '  if $dst { helper-call "bpf_get_stack" $task $dst 8 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_stack' arg0 expects raw context pointer"
    }
    {
        name: "source-helper-get-stack-accepts-map-buffer"
        category: "helper-state"
        tags: [helper stack-copy accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define get_stack_buf --kind array --value-type bytes:24 --max-entries 1'
            '  let buf = (0 | map-get get_stack_buf)'
            '  if $buf { helper-call "bpf_get_stack" $ctx $buf 24 0 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-stack-accepts-zero-size-buffer"
        category: "helper-state"
        tags: [helper stack-copy zero-size accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define get_stack_zero_buf --kind array --value-type bytes:24 --max-entries 1'
            '  let buf = (0 | map-get get_stack_zero_buf)'
            '  if $buf { helper-call "bpf_get_stack" $ctx $buf 0 2559 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-stack-rejects-small-buffer"
        category: "helper-state"
        tags: [helper stack-copy bounds reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define get_stack_small_buf --kind array --value-type bytes:8 --max-entries 1'
            '  let buf = (0 | map-get get_stack_small_buf)'
            '  if $buf { helper-call "bpf_get_stack" $ctx $buf 64 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper get_stack buf requires 64 bytes"
    }
    {
        name: "source-helper-get-stack-rejects-negative-size"
        category: "helper-state"
        tags: [helper stack-copy size reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define get_stack_negative_buf --kind array --value-type bytes:24 --max-entries 1'
            '  let buf = (0 | map-get get_stack_negative_buf)'
            '  let size = (0 - 1)'
            '  if $buf { helper-call "bpf_get_stack" $ctx $buf $size 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stack-copy helpers require arg2 size to be between 0 and u32::MAX"
    }
]
