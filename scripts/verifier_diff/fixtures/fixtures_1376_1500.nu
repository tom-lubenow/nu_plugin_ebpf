const VERIFIER_DIFF_FIXTURES_1376_1500 = [
    {
        name: "source-kfunc-task-release-rejects-double-release"
        category: "helper-state"
        tags: [kfunc ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    kfunc-call "bpf_task_release" $task'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "reference already released"
    }
    {
        name: "source-kfunc-task-release-rejects-cgroup-ref"
        category: "helper-state"
        tags: [kfunc ref-lifetime source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    kfunc-call "bpf_task_release" $cgrp'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects task reference, got cgroup reference"
    }
    {
        name: "source-helper-sk-lookup-release"
        category: "helper-state"
        tags: [helper-call socket ref-lifetime source accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let tuple = "0123456789ab"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 12 0 0)'
            '  let skc = (helper-call "bpf_skc_lookup_tcp" $ctx $tuple 12 0 0)'
            '  if $sk {'
            '    helper-call "bpf_sk_release" $sk'
            '  }'
            '  if $skc {'
            '    helper-call "bpf_sk_release" $skc'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-sk-lookup-udp-release"
        category: "helper-state"
        tags: [helper-call socket ref-lifetime source accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let tuple = "0123456789abcdef"'
            '  let sk = (helper-call "bpf_sk_lookup_udp" $ctx $tuple 16 0 0)'
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
        name: "source-helper-tcp-raw-syncookie"
        category: "helper-state"
        tags: [helper-call tcp syncookie source accept]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let ip4 = "01234567890123456789"'
            '  let ip6 = "0123456789012345678901234567890123456789"'
            '  let th = "01234567890123456789"'
            '  helper-call "bpf_tcp_raw_gen_syncookie_ipv4" $ip4 $th 20'
            '  helper-call "bpf_tcp_raw_gen_syncookie_ipv6" $ip6 $th 20'
            '  helper-call "bpf_tcp_raw_check_syncookie_ipv4" $ip4 $th'
            '  helper-call "bpf_tcp_raw_check_syncookie_ipv6" $ip6 $th'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-tcp-syncookie"
        category: "helper-state"
        tags: [helper-call tcp syncookie socket ref-lifetime source accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let tuple = "0123456789ab"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 12 0 0)'
            '  if $sk {'
            '    helper-call "bpf_tcp_check_syncookie" $sk $sk 20 $sk 20'
            '    helper-call "bpf_tcp_gen_syncookie" $sk $sk 20 $sk 20'
            '    helper-call "bpf_sk_release" $sk'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-sk-lookup-rejects-leak"
        category: "helper-state"
        tags: [helper-call socket ref-lifetime source reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let tuple = "0123456789abcdef"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 16 0 0)'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-helper-sk-release-accepts-lookup-or-null-release"
        category: "helper-state"
        tags: [helper-call socket ref-lifetime phi source accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let tuple = "0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let sk = (if $selector == 0 { helper-call "bpf_sk_lookup_tcp" $ctx $tuple 16 0 0 } else { 0 })'
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
            '  let tuple = "0123456789abcdef"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 16 0 0)'
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
            '  let tuple = "0123456789abcdef"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 16 0 0)'
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
            '  let tuple = "0123456789abcdef"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 16 0 0)'
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
    {
        name: "source-kfunc-crypto-ctx-create-release"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-ctx-acquire-release"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      let owned = (kfunc-call "bpf_crypto_ctx_acquire" $crypto)'
            '      if $owned {'
            '        $owned | kfunc-call "bpf_crypto_ctx_release"'
            '      }'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-ctx-acquire-rejects-owned-leak"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      let owned = (kfunc-call "bpf_crypto_ctx_acquire" $crypto)'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
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
        name: "source-kfunc-crypto-ctx-release-accepts-create-or-null-release"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  if $params {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let crypto = (if $selector == 0 { kfunc-call "bpf_crypto_ctx_create" $params 408 $err } else { 0 })'
            '    if $crypto {'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-ctx-create-record-field-err"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime record source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let rec = { err: "00000000" }'
            '  let err = $rec.err'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-ctx-create-rejects-leak"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      1 | count'
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
        name: "source-kfunc-crypto-encrypt-accepts-tracked-ctx"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = "0000000000000000"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_encrypt" $crypto $src $dst $siv'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-decrypt-accepts-tracked-ctx"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = "0000000000000000"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_decrypt" $crypto $src $dst $siv'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-encrypt-allows-null-siv"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_encrypt" $crypto $src $dst 0'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-encrypt-allows-zero-vreg-siv"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = 0'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_encrypt" $crypto $src $dst $siv'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-encrypt-rejects-nonzero-siv"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_encrypt" $crypto $src $dst 7'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_crypto_encrypt' arg3 expects null (0) or pointer"
    }
    {
        name: "source-kfunc-crypto-encrypt-rejects-nonzero-vreg-siv"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = 7'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_encrypt" $crypto $src $dst $siv'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_crypto_encrypt' arg3 expects null (0) or pointer"
    }
    {
        name: "source-kfunc-crypto-decrypt-allows-null-siv"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_decrypt" $crypto $src $dst 0'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-decrypt-rejects-nonzero-siv"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_decrypt" $crypto $src $dst 9'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_crypto_decrypt' arg3 expects null (0) or pointer"
    }
    {
        name: "source-kfunc-crypto-encrypt-rejects-kernel-src"
        category: "helper-state"
        tags: [kfunc crypto source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = "0000000000000000"'
            '  if $params {'
            '    if $task {'
            '      let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '      if $crypto {'
            '        kfunc-call "bpf_crypto_encrypt" $crypto $task $dst $siv'
            '        $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '      }'
            '      $task | kfunc-call "bpf_task_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc bpf_crypto_encrypt src expects pointer in [Stack, Map], got Kernel"
    }
    {
        name: "source-kfunc-crypto-decrypt-rejects-kernel-src"
        category: "helper-state"
        tags: [kfunc crypto source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = "0000000000000000"'
            '  if $params {'
            '    if $task {'
            '      let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '      if $crypto {'
            '        kfunc-call "bpf_crypto_decrypt" $crypto $task $dst $siv'
            '        $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '      }'
            '      $task | kfunc-call "bpf_task_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc bpf_crypto_decrypt src expects pointer in [Stack, Map], got Kernel"
    }
    {
        name: "source-kfunc-cgroup-acquire-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_acquire" $ctx.cgroup)'
            '  if $cgrp {'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cgroup-acquire-rejects-leak"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_acquire" $ctx.cgroup)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-cgroup-release-accepts-both-branch-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_acquire" $ctx.cgroup)'
            '  if $cgrp {'
            '    if $ctx.pid {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    } else {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cgroup-release-rejects-one-branch-release-leak"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_acquire" $ctx.cgroup)'
            '  if $cgrp {'
            '    if $ctx.pid {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
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
        name: "source-kfunc-cgroup-release-rejects-release-after-conditional-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_acquire" $ctx.cgroup)'
            '  if $cgrp {'
            '    if $ctx.pid {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    }'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_cgroup_release' arg0 reference already released"
    }
    {
        name: "source-kfunc-cgroup-release-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    kfunc-call "bpf_cgroup_release" $task'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects cgroup reference, got task reference"
    }
    {
        name: "source-kfunc-cgroup-from-id-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-task-get-cgroup1-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let cgrp = (kfunc-call "bpf_task_get_cgroup1" $task 0)'
            '    if $cgrp {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    }'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-task-get-cgroup1-rejects-cgroup-leak"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let cgrp = (kfunc-call "bpf_task_get_cgroup1" $task 0)'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-task-under-cgroup-accepts-task-and-cgroup"
        category: "helper-state"
        tags: [kfunc task cgroup source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let cgrp = (kfunc-call "bpf_task_get_cgroup1" $task 0)'
            '    if $cgrp {'
            '      let under = (kfunc-call "bpf_task_under_cgroup" $task $cgrp)'
            '      $under | count'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    }'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-task-under-cgroup-rejects-task-ref-cgroup-arg"
        category: "helper-state"
        tags: [kfunc task cgroup source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    kfunc-call "bpf_task_under_cgroup" $task $task'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg1 expects cgroup reference, got task reference"
    }
    {
        name: "source-kfunc-cgroup-release-accepts-acquire-or-null-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let cgrp = (if $selector == 0 { kfunc-call "bpf_cgroup_from_id" 1 } else { 0 })'
            '  if $cgrp {'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cgroup-ancestor-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    let parent = (kfunc-call "bpf_cgroup_ancestor" $cgrp 0)'
            '    if $parent {'
            '      $parent | kfunc-call "bpf_cgroup_release"'
            '    }'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cpumask-ref-release"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cpumask-ref-release-dtor"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    $mask | kfunc-call "bpf_cpumask_release_dtor"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cpumask-release-accepts-acquire-or-null-release"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let mask = (if $selector == 0 { kfunc-call "bpf_cpumask_create" } else { 0 })'
            '  if $mask {'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cpumask-ref-rejects-leak"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-cpumask-release-accepts-both-branch-release"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    if $ctx.pid {'
            '      $mask | kfunc-call "bpf_cpumask_release"'
            '    } else {'
            '      $mask | kfunc-call "bpf_cpumask_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cpumask-release-rejects-one-branch-release-leak"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    if $ctx.pid {'
            '      $mask | kfunc-call "bpf_cpumask_release"'
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
        name: "source-kfunc-cpumask-release-rejects-release-after-conditional-release"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    if $ctx.pid {'
            '      $mask | kfunc-call "bpf_cpumask_release"'
            '    }'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_cpumask_release' arg0 reference already released"
    }
    {
        name: "source-kfunc-cpumask-release-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    kfunc-call "bpf_cpumask_release" $task'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects cpumask reference, got task reference"
    }
    {
        name: "source-kfunc-cpumask-release-dtor-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    kfunc-call "bpf_cpumask_release_dtor" $task'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects cpumask reference, got task reference"
    }
    {
        name: "source-kfunc-cpumask-acquire-release"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    let owned = (kfunc-call "bpf_cpumask_acquire" $mask)'
            '    if $owned {'
            '      $owned | kfunc-call "bpf_cpumask_release"'
            '    }'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cpumask-acquire-rejects-owned-leak"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    let owned = (kfunc-call "bpf_cpumask_acquire" $mask)'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-cpumask-populate-release"
        category: "helper-state"
        tags: [kfunc cpumask source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    let bits = "0100000000000000"'
            '    let populated = (kfunc-call "bpf_cpumask_populate" $mask $bits 8)'
            '    $populated | count'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-cpumask-populate-rejects-scalar-mask"
        category: "helper-state"
        tags: [kfunc cpumask source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let bits = "0100000000000000"'
            '  kfunc-call "bpf_cpumask_populate" 7 $bits 8'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 expects pointer"
    }
    {
        name: "source-kfunc-cpumask-set-first-release"
        category: "helper-state"
        tags: [kfunc cpumask source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    kfunc-call "bpf_cpumask_set_cpu" 0 $mask'
            '    let first = (kfunc-call "bpf_cpumask_first" $mask)'
            '    $first | count'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cpumask-and-release"
        category: "helper-state"
        tags: [kfunc cpumask source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = (kfunc-call "bpf_cpumask_create")'
            '  if $dst {'
            '    let src = (kfunc-call "bpf_cpumask_create")'
            '    if $src {'
            '      kfunc-call "bpf_cpumask_set_cpu" 0 $src'
            '      let matched = (kfunc-call "bpf_cpumask_and" $dst $src $src)'
            '      $matched | count'
            '      $src | kfunc-call "bpf_cpumask_release"'
            '    }'
            '    $dst | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cpumask-and-rejects-scalar-arg"
        category: "helper-state"
        tags: [kfunc cpumask source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    kfunc-call "bpf_cpumask_and" $mask 7 $mask'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg1 expects pointer"
    }
    {
        name: "source-kfunc-cpumask-copy-query-release"
        category: "helper-state"
        tags: [kfunc cpumask source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = (kfunc-call "bpf_cpumask_create")'
            '  if $dst {'
            '    let src = (kfunc-call "bpf_cpumask_create")'
            '    if $src {'
            '      kfunc-call "bpf_cpumask_setall" $src'
            '      kfunc-call "bpf_cpumask_copy" $dst $src'
            '      let equal = (kfunc-call "bpf_cpumask_equal" $dst $src)'
            '      let intersects = (kfunc-call "bpf_cpumask_intersects" $dst $src)'
            '      let test = (kfunc-call "bpf_cpumask_test_cpu" 0 $dst)'
            '      ($equal + $intersects + $test) | count'
            '      $src | kfunc-call "bpf_cpumask_release"'
            '    }'
            '    $dst | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-cpumask-test-cpu-rejects-scalar-mask"
        category: "helper-state"
        tags: [kfunc cpumask source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_cpumask_test_cpu" 0 7'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg1 expects pointer"
    }
    {
        name: "source-kfunc-cpumask-single-mask-query-release"
        category: "helper-state"
        tags: [kfunc cpumask source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    kfunc-call "bpf_cpumask_clear" $mask'
            '    let empty = (kfunc-call "bpf_cpumask_empty" $mask)'
            '    kfunc-call "bpf_cpumask_setall" $mask'
            '    let full = (kfunc-call "bpf_cpumask_full" $mask)'
            '    kfunc-call "bpf_cpumask_clear_cpu" 0 $mask'
            '    let was_set = (kfunc-call "bpf_cpumask_test_and_set_cpu" 0 $mask)'
            '    let cleared = (kfunc-call "bpf_cpumask_test_and_clear_cpu" 0 $mask)'
            '    let first_zero = (kfunc-call "bpf_cpumask_first_zero" $mask)'
            '    let weight = (kfunc-call "bpf_cpumask_weight" $mask)'
            '    ($empty + $full + $was_set + $cleared + $first_zero + $weight) | count'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-cpumask-setops-release"
        category: "helper-state"
        tags: [kfunc cpumask source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = (kfunc-call "bpf_cpumask_create")'
            '  if $dst {'
            '    let src = (kfunc-call "bpf_cpumask_create")'
            '    if $src {'
            '      kfunc-call "bpf_cpumask_set_cpu" 0 $dst'
            '      kfunc-call "bpf_cpumask_setall" $src'
            '      let first_and = (kfunc-call "bpf_cpumask_first_and" $dst $src)'
            '      let subset = (kfunc-call "bpf_cpumask_subset" $dst $src)'
            '      let any = (kfunc-call "bpf_cpumask_any_distribute" $src)'
            '      let any_and = (kfunc-call "bpf_cpumask_any_and_distribute" $dst $src)'
            '      kfunc-call "bpf_cpumask_or" $dst $dst $src'
            '      kfunc-call "bpf_cpumask_xor" $dst $dst $src'
            '      ($first_and + $subset + $any + $any_and) | count'
            '      $src | kfunc-call "bpf_cpumask_release"'
            '    }'
            '    $dst | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kptr-xchg-task-ref-transfer"
        category: "helper-state"
        tags: [kfunc helper-call kptr ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --key-type u32 --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let entry = (0 | map-get task_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.task $task)'
            '      if $old {'
            '        $old | kfunc-call "bpf_task_release"'
            '      }'
            '    } else {'
            '      $task | kfunc-call "bpf_task_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kptr-xchg-cgroup-clear-requires-null-checked-dst"
        category: "helper-state"
        tags: [helper-call kptr cgroup source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get cgroup_slots --kind array)'
            '  helper-call "bpf_kptr_xchg" $entry.cgrp 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper kptr_xchg dst may dereference null pointer"
    }
    {
        name: "source-kptr-xchg-rejects-old-ref-leak"
        category: "helper-state"
        tags: [kfunc helper-call kptr ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --key-type u32 --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let entry = (0 | map-get task_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.task $task)'
            '      0'
            '    } else {'
            '      $task | kfunc-call "bpf_task_release"'
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
        name: "source-kptr-xchg-old-ref-accepts-both-branch-release"
        category: "helper-state"
        tags: [kfunc helper-call kptr ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --key-type u32 --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let entry = (0 | map-get task_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.task $task)'
            '      if $old {'
            '        if $ctx.pid {'
            '          $old | kfunc-call "bpf_task_release"'
            '        } else {'
            '          $old | kfunc-call "bpf_task_release"'
            '        }'
            '      }'
            '    } else {'
            '      $task | kfunc-call "bpf_task_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kptr-xchg-old-ref-rejects-one-branch-release-leak"
        category: "helper-state"
        tags: [kfunc helper-call kptr ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --key-type u32 --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let entry = (0 | map-get task_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.task $task)'
            '      if $old {'
            '        if $ctx.pid {'
            '          $old | kfunc-call "bpf_task_release"'
            '        }'
            '      }'
            '    } else {'
            '      $task | kfunc-call "bpf_task_release"'
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
        name: "source-kptr-xchg-old-ref-rejects-release-after-conditional-release"
        category: "helper-state"
        tags: [kfunc helper-call kptr ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --key-type u32 --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let entry = (0 | map-get task_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.task $task)'
            '      if $old {'
            '        if $ctx.pid {'
            '          $old | kfunc-call "bpf_task_release"'
            '        }'
            '        $old | kfunc-call "bpf_task_release"'
            '      }'
            '    } else {'
            '      $task | kfunc-call "bpf_task_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_task_release' arg0 reference already released"
    }
    {
        name: "source-kptr-xchg-cpumask-ref-transfer"
        category: "helper-state"
        tags: [kfunc helper-call kptr cpumask ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define mask_slots --kind array --key-type u32 --value-type "record{mask:kptr:bpf_cpumask,cookie:u64}" --max-entries 1'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    let entry = (0 | map-get mask_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.mask $mask)'
            '      if $old {'
            '        $old | kfunc-call "bpf_cpumask_release"'
            '      }'
            '    } else {'
            '      $mask | kfunc-call "bpf_cpumask_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kptr-xchg-cpumask-rejects-old-ref-leak"
        category: "helper-state"
        tags: [kfunc helper-call kptr cpumask ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define mask_slots --kind array --key-type u32 --value-type "record{mask:kptr:bpf_cpumask,cookie:u64}" --max-entries 1'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    let entry = (0 | map-get mask_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.mask $mask)'
            '      0'
            '    } else {'
            '      $mask | kfunc-call "bpf_cpumask_release"'
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
        name: "source-kptr-xchg-file-ref-transfer"
        category: "helper-state"
        tags: [kfunc helper-call kptr file ref-lifetime source accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  map-define file_slots --kind array --key-type u32 --value-type "record{file:kptr:file,cookie:u64}" --max-entries 1'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  if $file {'
            '    let entry = (0 | map-get file_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.file $file)'
            '      if $old {'
            '        $old | kfunc-call "bpf_put_file"'
            '      }'
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
        name: "source-kptr-xchg-file-rejects-old-ref-leak"
        category: "helper-state"
        tags: [kfunc helper-call kptr file ref-lifetime source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  map-define file_slots --kind array --key-type u32 --value-type "record{file:kptr:file,cookie:u64}" --max-entries 1'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  if $file {'
            '    let entry = (0 | map-get file_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.file $file)'
            '      0'
            '    } else {'
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
        name: "source-kptr-xchg-cgroup-ref-transfer"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    let entry = (0 | map-get cgroup_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.cgrp $cgrp)'
            '      if $old {'
            '        $old | kfunc-call "bpf_cgroup_release"'
            '      }'
            '    } else {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kptr-xchg-cgroup-clear-release"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get cgroup_slots --kind array)'
            '  if $entry {'
            '    let old = (helper-call "bpf_kptr_xchg" $entry.cgrp 0)'
            '    if $old {'
            '      $old | kfunc-call "bpf_cgroup_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kptr-xchg-cgroup-clear-zero-vreg-release"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let zero = 0'
            '  let entry = (0 | map-get cgroup_slots --kind array)'
            '  if $entry {'
            '    let old = (helper-call "bpf_kptr_xchg" $entry.cgrp $zero)'
            '    if $old {'
            '      $old | kfunc-call "bpf_cgroup_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kptr-xchg-cgroup-clear-conditional-null-old-release"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get cgroup_slots --kind array)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let old = (if $selector == 0 { helper-call "bpf_kptr_xchg" $entry.cgrp 0 } else { 0 })'
            '    if $old {'
            '      $old | kfunc-call "bpf_cgroup_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kptr-xchg-cgroup-clear-rejects-conditional-old-release"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get cgroup_slots --kind array)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let old = (helper-call "bpf_kptr_xchg" $entry.cgrp 0)'
            '    if $selector == 0 {'
            '      if $old {'
            '        $old | kfunc-call "bpf_cgroup_release"'
            '      }'
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
        name: "source-kptr-xchg-rejects-nonzero-scalar-src"
        category: "helper-state"
        tags: [helper-call kptr cgroup source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let one = 1'
            '  let entry = (0 | map-get cgroup_slots --kind array)'
            '  if $entry {'
            '    helper-call "bpf_kptr_xchg" $entry.cgrp $one'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 194 arg1 expects pointer, got I64"
    }
    {
        name: "source-kptr-xchg-cgroup-clear-rejects-old-ref-leak"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get cgroup_slots --kind array)'
            '  if $entry {'
            '    let old = (helper-call "bpf_kptr_xchg" $entry.cgrp 0)'
            '    0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kptr-xchg-rejects-pointee-mismatch"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --key-type u32 --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    let entry = (0 | map-get task_slots --kind array)'
            '    if $entry {'
            '      helper-call "bpf_kptr_xchg" $entry.task $cgrp'
            '    } else {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot store cgroup pointer in kptr:task_struct slot"
    }
    {
        name: "source-kfunc-res-spin-rejects-non-kernel-pointer"
        category: "helper-state"
        tags: [kfunc res-spin-lock source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_res_spin_lock" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_res_spin_lock' arg0 expects pointer"
    }
    {
        name: "source-kfunc-throw"
        category: "helper-state"
        tags: [kfunc throw source accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_throw" 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-throw-rejects-return-use"
        category: "helper-state"
        tags: [kfunc throw source void-return reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_throw" 1 | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "void kfunc 'bpf_throw' return value cannot be used"
    }
    {
        name: "source-kfunc-rcu-read-lock-unlock"
        category: "helper-state"
        tags: [kfunc rcu source accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_lock"'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rcu-read-lock-user-function-unlock"
        category: "helper-state"
        tags: [kfunc rcu source accept user-function]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def lock [] {'
            '    kfunc-call "bpf_rcu_read_lock"'
            '    0'
            '  }'
            '  def unlock [] {'
            '    kfunc-call "bpf_rcu_read_unlock"'
            '    0'
            '  }'
            '  lock'
            '  unlock'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rcu-read-lock-rejects-return-use"
        category: "helper-state"
        tags: [kfunc rcu source void-return reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_lock" | count'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "void kfunc 'bpf_rcu_read_lock' return value cannot be used"
    }
    {
        name: "source-kfunc-rcu-read-unlock-rejects-unmatched"
        category: "helper-state"
        tags: [kfunc rcu source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_rcu_read_lock"
    }
    {
        name: "source-kfunc-rcu-read-lock-rejects-leak"
        category: "helper-state"
        tags: [kfunc rcu source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_lock"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased RCU read lock"
    }
    {
        name: "source-kfunc-rcu-read-unlock-rejects-mixed-join"
        category: "helper-state"
        tags: [kfunc rcu source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_rcu_read_lock"'
            '  }'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_rcu_read_lock"
    }
    {
        name: "source-kfunc-rcu-read-lock-rejects-branch-leak"
        category: "helper-state"
        tags: [kfunc rcu source branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_rcu_read_lock"'
            '  } else {'
            '    kfunc-call "bpf_rcu_read_lock"'
            '    kfunc-call "bpf_rcu_read_unlock"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased RCU read lock"
    }
    {
        name: "source-kfunc-preempt-disable-enable"
        category: "helper-state"
        tags: [kfunc preempt source accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_preempt_disable"'
            '  kfunc-call "bpf_preempt_enable"'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-preempt-disable-user-function-enable"
        category: "helper-state"
        tags: [kfunc preempt source accept user-function]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def disable [] {'
            '    kfunc-call "bpf_preempt_disable"'
            '    0'
            '  }'
            '  def enable [] {'
            '    kfunc-call "bpf_preempt_enable"'
            '    0'
            '  }'
            '  disable'
            '  enable'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-preempt-enable-rejects-unmatched"
        category: "helper-state"
        tags: [kfunc preempt source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_preempt_enable"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_preempt_disable"
    }
    {
        name: "source-kfunc-preempt-disable-rejects-leak"
        category: "helper-state"
        tags: [kfunc preempt source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_preempt_disable"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased preempt disable"
    }
    {
        name: "source-kfunc-preempt-enable-rejects-mixed-join"
        category: "helper-state"
        tags: [kfunc preempt source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_preempt_disable"'
            '  }'
            '  kfunc-call "bpf_preempt_enable"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_preempt_disable"
    }
    {
        name: "source-kfunc-preempt-disable-rejects-branch-leak"
        category: "helper-state"
        tags: [kfunc preempt source branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_preempt_disable"'
            '  } else {'
            '    kfunc-call "bpf_preempt_disable"'
            '    kfunc-call "bpf_preempt_enable"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased preempt disable"
    }
    {
        name: "source-kfunc-local-irq-save-restore"
        category: "helper-state"
        tags: [kfunc irq source accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_local_irq_save" $flags'
            '  kfunc-call "bpf_local_irq_restore" $flags'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-local-irq-user-function-save-restore"
        category: "helper-state"
        tags: [kfunc irq source accept user-function]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def save [flags] {'
            '    kfunc-call "bpf_local_irq_save" $flags'
            '    0'
            '  }'
            '  def restore [flags] {'
            '    kfunc-call "bpf_local_irq_restore" $flags'
            '    0'
            '  }'
            '  let flags = "00000000"'
            '  save $flags'
            '  restore $flags'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-local-irq-restore-rejects-unmatched"
        category: "helper-state"
        tags: [kfunc irq source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_local_irq_restore" $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_local_irq_save"
    }
]
