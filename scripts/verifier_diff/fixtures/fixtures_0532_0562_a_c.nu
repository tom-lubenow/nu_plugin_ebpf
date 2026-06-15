const VERIFIER_DIFF_FIXTURES_0532_0562_A_C = [
    {
        name: "dynptr-kfunc-copy-from-user-initializes-dynptr"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_dynptr" $d 0 4 $ptr'
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
        name: "dynptr-kfunc-copy-from-user-rejects-reinitialize"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_dynptr" $d 0 4 $ptr'
            '    kfunc-call "bpf_copy_from_user_dynptr" $d 0 4 $ptr'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_copy_from_user_dynptr' arg0 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-kfunc-copy-from-user-task-initializes-dynptr"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_task_dynptr" $d 0 4 $ptr $ctx.current_task'
            '    let size = (kfunc-call "bpf_dynptr_size" $d)'
            '    $size | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
