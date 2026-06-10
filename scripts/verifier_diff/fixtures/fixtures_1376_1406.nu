const VERIFIER_DIFF_FIXTURES_1376_1406 = [
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
]
