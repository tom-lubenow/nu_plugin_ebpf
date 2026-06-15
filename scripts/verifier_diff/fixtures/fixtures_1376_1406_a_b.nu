const VERIFIER_DIFF_FIXTURES_1376_1406_A_B = [
    {
        name: "source-helper-sk-release-accepts-lookup-or-null-release"
        category: "helper-state"
        tags: [helper-call socket ref-lifetime phi source accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let tuple = "0123456789ab"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let sk = (if $selector == 0 { helper-call "bpf_sk_lookup_tcp" $ctx $tuple 12 0 0 } else { 0 })'
            '  if $sk {'
            '    helper-call "bpf_sk_release" $sk'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-sk-release-rejects-unchecked-null"
        category: "helper-state"
        tags: [helper-call socket ref-lifetime source reject nullability]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let tuple = "0123456789ab"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 12 0 0)'
            '  helper-call "bpf_sk_release" $sk'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper sk_release sock may dereference null pointer"
    }
    {
        name: "source-helper-sk-release-rejects-double-release"
        category: "helper-state"
        tags: [helper-call socket ref-lifetime source reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let tuple = "0123456789ab"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 12 0 0)'
            '  if $sk {'
            '    helper-call "bpf_sk_release" $sk'
            '    helper-call "bpf_sk_release" $sk'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "reference already released"
    }
    {
        name: "source-helper-sk-release-rejects-use-after-release"
        category: "helper-state"
        tags: [helper-call socket ref-lifetime source reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let tuple = "0123456789ab"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 12 0 0)'
            '  if $sk {'
            '    helper-call "bpf_sk_release" $sk'
            '    $sk.family | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "reference already released"
    }
    {
        name: "source-helper-sk-release-rejects-task-ref"
        category: "helper-state"
        tags: [helper-call socket ref-lifetime source reject]
        requires: [loopback-interface kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    helper-call "bpf_sk_release" $task'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_release' arg0 expects socket pointer"
    }
    {
        name: "source-kfunc-file-ref-release"
        category: "helper-state"
        tags: [kfunc file ref-lifetime source accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  if $file {'
            '    $file | kfunc-call "bpf_put_file"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-file-ref-project-release"
        category: "helper-state"
        tags: [kfunc file ref-lifetime source metadata accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  if $file {'
            '    $file.f_mode | count'
            '    $file | kfunc-call "bpf_put_file"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-file-release-accepts-acquire-or-null-release"
        category: "helper-state"
        tags: [kfunc file ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let file = (if $selector == 0 { kfunc-call "bpf_get_task_exe_file" $ctx.current_task } else { 0 })'
            '  if $file {'
            '    $file | kfunc-call "bpf_put_file"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
