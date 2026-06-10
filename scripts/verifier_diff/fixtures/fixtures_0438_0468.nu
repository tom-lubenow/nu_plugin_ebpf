const VERIFIER_DIFF_FIXTURES_0438_0468 = [
    {
        name: "ringbuf-dynptr-discard-rejects-dynamic-wakeup-flags"
        category: "helper-state"
        tags: [ringbuf dynptr flags ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_discard_dynptr' requires arg1 flags to contain only BPF_RB_* wakeup bits"
    }
    {
        name: "dynptr-data-rejects-uninitialized"
        category: "helper-state"
        tags: [dynptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_dynptr_data" $d 0 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires initialized dynptr stack object"
    }
    {
        name: "dynptr-from-mem-initializes-map-value"
        category: "helper-state"
        tags: [dynptr accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    let ptr = (helper-call "bpf_dynptr_data" $d 0 4)'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-from-mem-rejects-reinitialize"
        category: "helper-state"
        tags: [dynptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_reinit_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_reinit_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_from_mem' arg3 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-from-mem-rejects-nonzero-flags"
        category: "helper-state"
        tags: [dynptr flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_flag_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_flag_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 1 $d'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_from_mem' requires arg2 flags to be 0"
    }
    {
        name: "dynptr-from-mem-rejects-dynamic-flags"
        category: "helper-state"
        tags: [dynptr flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_dynamic_flag_buffers 0 --kind array'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get dynptr_dynamic_flag_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 $flags $d'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_from_mem' requires arg2 flags to be 0"
    }
    {
        name: "dynptr-from-mem-accepts-both-branch-initialization"
        category: "helper-state"
        tags: [dynptr phi accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_join_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_join_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    } else {'
            '      helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    }'
            '    helper-call "bpf_dynptr_data" $d 0 4'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-from-mem-rejects-one-branch-initialization"
        category: "helper-state"
        tags: [dynptr phi reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_join_partial_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_join_partial_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    }'
            '    helper-call "bpf_dynptr_data" $d 0 4'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_data' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-from-mem-rejects-reinit-after-one-branch-initialization"
        category: "helper-state"
        tags: [dynptr phi reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_reinit_join_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_reinit_join_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    }'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_from_mem' arg3 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-read-write-initialized-from-mem"
        category: "helper-state"
        tags: [dynptr accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_rw_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_rw_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let out = "0000"'
            '    let src = "wxyz"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    helper-call "bpf_dynptr_write" $d 0 $src 4 0'
            '    helper-call "bpf_dynptr_read" $out 4 $d 0 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-read-rejects-uninitialized"
        category: "helper-state"
        tags: [dynptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let out = "0000"'
            '  helper-call "bpf_dynptr_read" $out 4 $d 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_read' arg2 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-read-rejects-nonzero-flags"
        category: "helper-state"
        tags: [dynptr flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_read_flag_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_read_flag_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let out = "0000"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    helper-call "bpf_dynptr_read" $out 4 $d 0 1'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_read' requires arg4 flags to be 0"
    }
    {
        name: "dynptr-read-rejects-dynamic-flags"
        category: "helper-state"
        tags: [dynptr flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_read_dynamic_flag_buffers 0 --kind array'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get dynptr_read_dynamic_flag_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let out = "0000"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    helper-call "bpf_dynptr_read" $out 4 $d 0 $flags'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_read' requires arg4 flags to be 0"
    }
    {
        name: "dynptr-read-rejects-use-after-ringbuf-submit"
        category: "helper-state"
        tags: [dynptr ringbuf ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let out = "0000"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  helper-call "bpf_dynptr_read" $out 4 $d 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_read' arg2 ringbuf dynptr reservation already released"
    }
    {
        name: "dynptr-write-rejects-uninitialized"
        category: "helper-state"
        tags: [dynptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let src = "wxyz"'
            '  helper-call "bpf_dynptr_write" $d 0 $src 4 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_write' arg0 requires initialized dynptr stack object"
    }
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
