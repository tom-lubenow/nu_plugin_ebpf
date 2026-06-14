const VERIFIER_DIFF_FIXTURES_0532_0562_B = [
    {
        name: "dynptr-kfunc-copy-from-user-task-str-initializes-dynptr"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_task_str_dynptr" $d 0 4 $ptr $ctx.current_task'
            '    let size = (kfunc-call "bpf_dynptr_size" $d)'
            '    $size | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-copy-from-user-str-accepts-user-src"
        category: "helper-state"
        tags: [kfunc copy-user source accept]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let dst = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_str" $dst 8 $ptr 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-copy-from-user-str-rejects-stack-src"
        category: "helper-state"
        tags: [kfunc copy-user source reject]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let dst = "0123456789abcdef"'
            '  let src = "abcdefgh"'
            '  kfunc-call "bpf_copy_from_user_str" $dst 8 $src 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_copy_from_user_str' arg2 expects user pointer, got Stack"
    }
    {
        name: "source-kfunc-copy-from-user-task-str-accepts-current-task"
        category: "helper-state"
        tags: [kfunc copy-user source accept]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let dst = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_task_str" $dst 8 $ptr $ctx.current_task 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-copy-from-user-task-str-rejects-stack-task"
        category: "helper-state"
        tags: [kfunc copy-user source reject]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let dst = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_task_str" $dst 8 $ptr $dst 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_copy_from_user_task_str' arg3 expects kernel pointer, got Stack"
    }
    {
        name: "source-kfunc-copy-from-user-dynptr-rejects-stack-src"
        category: "helper-state"
        tags: [kfunc copy-user dynptr source reject]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let src = "abcdefgh"'
            '  kfunc-call "bpf_copy_from_user_dynptr" $d 0 4 $src'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_copy_from_user_dynptr' arg3 expects user pointer, got Stack"
    }
    {
        name: "source-kfunc-copy-from-user-task-dynptr-rejects-stack-task"
        category: "helper-state"
        tags: [kfunc copy-user dynptr source reject]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_task_dynptr" $d 0 4 $ptr $d'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_copy_from_user_task_dynptr' arg4 expects kernel pointer, got Stack"
    }
    {
        name: "source-kfunc-copy-from-user-task-str-dynptr-rejects-stack-task"
        category: "helper-state"
        tags: [kfunc copy-user dynptr source reject]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_task_str_dynptr" $d 0 4 $ptr $d'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_copy_from_user_task_str_dynptr' arg4 expects kernel pointer, got Stack"
    }
    {
        name: "dynptr-kfunc-from-xdp-initializes-dynptr"
        category: "helper-state"
        tags: [kfunc dynptr xdp accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_xdp" $ctx 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-xdp-copied-raw-context"
        category: "helper-state"
        tags: [kfunc dynptr xdp accept context-alias]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let raw_ctx = $ctx'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_xdp" $raw_ctx 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-xdp-user-function-raw-context"
        category: "helper-state"
        tags: [kfunc dynptr xdp accept user-function]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def init [raw_ctx] {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_dynptr_from_xdp" $raw_ctx 0 $d'
            '    let size = (kfunc-call "bpf_dynptr_size" $d)'
            '    $size | count'
            '    0'
            '  }'
            '  init $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-xdp-returned-raw-context"
        category: "helper-state"
        tags: [kfunc dynptr xdp accept user-function source metadata]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def get_ctx [event] { $event }'
            '  let raw_ctx = (get_ctx $ctx)'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_xdp" $raw_ctx 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-xdp-rejects-reinitialize"
        category: "helper-state"
        tags: [kfunc dynptr xdp reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_xdp" $ctx 0 $d'
            '  kfunc-call "bpf_dynptr_from_xdp" $ctx 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_xdp' arg2 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-kfunc-from-xdp-rejects-packet-arg"
        category: "helper-state"
        tags: [kfunc dynptr xdp source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_xdp" $ctx.data 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_xdp' arg0 expects xdp_md pointer"
    }
    {
        name: "dynptr-kfunc-from-xdp-rejects-nonzero-flags"
        category: "helper-state"
        tags: [kfunc dynptr xdp flags reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_xdp" $ctx 1 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_xdp' arg1 must be known zero"
    }
    {
        name: "dynptr-kfunc-from-xdp-rejects-dynamic-flags"
        category: "helper-state"
        tags: [kfunc dynptr xdp flags reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  kfunc-call "bpf_dynptr_from_xdp" $ctx $flags $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_xdp' arg1 must be known zero"
    }
]
