const VERIFIER_DIFF_FIXTURES_0438_0468_B = [
    {
        name: "dynptr-write-rejects-nonzero-flags"
        category: "helper-state"
        tags: [dynptr flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_write_flag_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_write_flag_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let src = "wxyz"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    helper-call "bpf_dynptr_write" $d 0 $src 4 1'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_write' requires arg4 flags to be 0 for modeled dynptr sources"
    }
    {
        name: "dynptr-write-rejects-dynamic-flags"
        category: "helper-state"
        tags: [dynptr flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_write_dynamic_flag_buffers 0 --kind array'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get dynptr_write_dynamic_flag_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let src = "wxyz"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    helper-call "bpf_dynptr_write" $d 0 $src 4 $flags'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_write' requires arg4 flags to be 0 for modeled dynptr sources"
    }
    {
        name: "dynptr-write-rejects-use-after-ringbuf-submit"
        category: "helper-state"
        tags: [dynptr ringbuf ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let src = "wxyz"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  helper-call "bpf_dynptr_write" $d 0 $src 4 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_write' arg0 ringbuf dynptr reservation already released"
    }
    {
        name: "dynptr-data-rejects-use-after-ringbuf-submit"
        category: "helper-state"
        tags: [dynptr ringbuf ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  helper-call "bpf_dynptr_data" $d 0 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_data' arg0 ringbuf dynptr reservation already released"
    }
    {
        name: "source-helper-copy-from-user-accepts-user-src"
        category: "helper-state"
        tags: [helper copy-user accept]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let dst = "0123456789abcdef"'
            '    helper-call "bpf_copy_from_user" $dst 8 $ptr'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-copy-from-user-task-accepts-current-task"
        category: "helper-state"
        tags: [helper copy-user accept]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let dst = "0123456789abcdef"'
            '    helper-call "bpf_copy_from_user_task" $dst 8 $ptr $ctx.current_task 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-copy-from-user-task-rejects-dynamic-flags"
        category: "helper-state"
        tags: [helper copy-user flags reject]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let dst = "0123456789abcdef"'
            '    let flags = (helper-call "bpf_get_prandom_u32")'
            '    helper-call "bpf_copy_from_user_task" $dst 8 $ptr $ctx.current_task $flags'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_copy_from_user_task' requires arg4 = 0"
    }
    {
        name: "source-helper-copy-from-user-accepts-zero-size-null-dst"
        category: "helper-state"
        tags: [helper copy-user zero-size accept]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    helper-call "bpf_copy_from_user" 0 0 $ptr'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-copy-from-user-rejects-null-dst-nonzero-size"
        category: "helper-state"
        tags: [helper copy-user zero-size reject]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    helper-call "bpf_copy_from_user" 0 8 $ptr'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 148 arg0 requires arg1 = 0 when arg0 is null"
    }
    {
        name: "source-helper-copy-from-user-rejects-null-dst-dynamic-size"
        category: "helper-state"
        tags: [helper copy-user zero-size dynamic reject]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let size = (helper-call "bpf_get_prandom_u32")'
            '    helper-call "bpf_copy_from_user" 0 $size $ptr'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 148 arg0 requires arg1 = 0 when arg0 is null"
    }
    {
        name: "source-helper-copy-from-user-rejects-stack-src"
        category: "helper-state"
        tags: [helper copy-user reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "0123456789abcdef"'
            '  let src = "abcdefgh"'
            '  helper-call "bpf_copy_from_user" $dst 8 $src'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper copy_from_user src expects pointer in [User]"
    }
]
