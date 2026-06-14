const VERIFIER_DIFF_FIXTURES_1376_1406_B = [
    {
        name: "source-kfunc-file-ref-rejects-leak"
        category: "helper-state"
        tags: [kfunc file ref-lifetime source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-file-release-accepts-both-branch-release"
        category: "helper-state"
        tags: [kfunc file ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  if $file {'
            '    if $ctx.pid {'
            '      $file | kfunc-call "bpf_put_file"'
            '    } else {'
            '      $file | kfunc-call "bpf_put_file"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-file-release-rejects-one-branch-release-leak"
        category: "helper-state"
        tags: [kfunc file ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  if $file {'
            '    if $ctx.pid {'
            '      $file | kfunc-call "bpf_put_file"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-file-release-rejects-release-after-conditional-release"
        category: "helper-state"
        tags: [kfunc file ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  if $file {'
            '    if $ctx.pid {'
            '      $file | kfunc-call "bpf_put_file"'
            '    }'
            '    $file | kfunc-call "bpf_put_file"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_put_file' arg0 reference already released"
    }
    {
        name: "source-kfunc-file-release-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc file ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    kfunc-call "bpf_put_file" $task'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects file reference, got task reference"
    }
    {
        name: "source-helper-d-path-accepts-file-path"
        category: "helper-state"
        tags: [helper-call file path source accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  helper-call "bpf_d_path" $ctx.arg0.f_path $buf 64'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-d-path-rejects-stack-path"
        category: "helper-state"
        tags: [helper-call file path source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  helper-call "bpf_d_path" $buf $buf 64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper d_path path expects pointer in [Kernel]"
    }
    {
        name: "source-helper-d-path-accepts-zero-size-null-buffer"
        category: "helper-state"
        tags: [helper-call file path source zero-size accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_d_path" $ctx.arg0.f_path 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-d-path-rejects-small-buffer"
        category: "helper-state"
        tags: [helper-call file path source bounds reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "01234567"'
            '  helper-call "bpf_d_path" $ctx.arg0.f_path $buf 64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper d_path buf"
    }
    {
        name: "source-helper-d-path-rejects-negative-size"
        category: "helper-state"
        tags: [helper-call file path source size reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef"'
            '  let size = (0 - 1)'
            '  helper-call "bpf_d_path" $ctx.arg0.f_path $buf $size'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_d_path' requires arg2 size to be between 0 and u32::MAX"
    }
    {
        name: "source-helper-d-path-rejects-dynamic-negative-size"
        category: "helper-state"
        tags: [helper-call file path source size dynamic reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef"'
            '  let size = (0 - (helper-call "bpf_get_prandom_u32"))'
            '  helper-call "bpf_d_path" $ctx.arg0.f_path $buf $size'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_d_path' requires arg2 size to be between 0 and u32::MAX"
    }
    {
        name: "source-helper-d-path-pipeline-requires-explicit-path"
        category: "helper-state"
        tags: [helper-call file path source reject pipeline diagnostic]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  $ctx.arg0.f_path | helper-call "bpf_d_path" $buf 64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "pass that value explicitly as the first helper argument"
    }
    {
        name: "source-helper-call-prior-statement-does-not-inject"
        category: "helper-state"
        tags: [helper-call source reject pipeline diagnostic]
        target: "kprobe:sys_read"
        program: [
            '{|ctx|'
            '  99'
            '  helper-call "bpf_get_socket_cookie"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects 1..=1 helper arguments after the helper name, got 0"
    }
    {
        name: "source-kfunc-call-prior-statement-does-not-inject"
        category: "helper-state"
        tags: [kfunc source reject pipeline diagnostic]
        target: "kprobe:sys_read"
        program: [
            '{|ctx|'
            '  99'
            '  kfunc-call "bpf_cgroup_ancestor" 7 --btf-id 4242'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects 2..=2 arguments, got 1"
    }
    {
        name: "source-kfunc-path-d-path-accepts-file-path"
        category: "helper-state"
        tags: [kfunc file path source accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  kfunc-call "bpf_path_d_path" $ctx.arg0.f_path $buf 64'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-path-d-path-pipeline-file-path"
        category: "helper-state"
        tags: [kfunc file path source accept pipeline]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  $ctx.arg0.f_path | kfunc-call "bpf_path_d_path" $buf 64'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
