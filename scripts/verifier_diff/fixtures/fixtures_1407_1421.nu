const VERIFIER_DIFF_FIXTURES_1407_1421 = [
    {
        name: "source-kfunc-path-d-path-rejects-stack-path"
        category: "helper-state"
        tags: [kfunc file path source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  kfunc-call "bpf_path_d_path" $buf $buf 64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_path_d_path' arg0 expects kernel pointer"
    }
    {
        name: "source-kfunc-path-d-path-rejects-kernel-buffer"
        category: "helper-state"
        tags: [kfunc file path source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_path_d_path" $ctx.arg0.f_path $ctx.arg0 64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc path_d_path buffer expects pointer in [Stack, Map], got Kernel"
    }
    {
        name: "source-kfunc-path-d-path-rejects-small-buffer"
        category: "helper-state"
        tags: [kfunc file path source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef"'
            '  kfunc-call "bpf_path_d_path" $ctx.arg0.f_path $buf 64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc path_d_path buffer requires 64 bytes"
    }
    {
        name: "source-kfunc-path-d-path-rejects-zero-size"
        category: "helper-state"
        tags: [kfunc file path source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  kfunc-call "bpf_path_d_path" $ctx.arg0.f_path $buf 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_path_d_path' arg2 must be > 0"
    }
    {
        name: "source-kfunc-path-d-path-rejects-dynamic-zero-size"
        category: "helper-state"
        tags: [kfunc file path source dynamic branch reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let size = (if $selector == 0 { 0 } else { 64 })'
            '  kfunc-call "bpf_path_d_path" $ctx.arg0.f_path $buf $size'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_path_d_path' arg2 must be > 0"
    }
    {
        name: "source-kfunc-crypto-ctx-release-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    kfunc-call "bpf_crypto_ctx_release" $task'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects crypto_ctx reference, got task reference"
    }
    {
        name: "source-kfunc-crypto-encrypt-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = "0000000000000000"'
            '  if $task {'
            '    kfunc-call "bpf_crypto_encrypt" $task $src $dst $siv'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 expects crypto_ctx reference, got task reference"
    }
    {
        name: "source-kfunc-crypto-ctx-create-rejects-kernel-params"
        category: "helper-state"
        tags: [kfunc crypto source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  let err = "00000000"'
            '  if $task {'
            '    kfunc-call "bpf_crypto_ctx_create" $task 408 $err'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc bpf_crypto_ctx_create params expects pointer in [Stack, Map], got Kernel"
    }
]
