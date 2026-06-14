const VERIFIER_DIFF_FIXTURES_1376_1406_A = [
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
            '  let tuple = "0123456789ab"'
            '  let sk = (helper-call "bpf_sk_lookup_udp" $ctx $tuple 12 0 0)'
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
            '  let tuple = "0123456789ab"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 12 0 0)'
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
