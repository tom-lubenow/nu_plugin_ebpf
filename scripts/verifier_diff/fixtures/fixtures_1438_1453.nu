const VERIFIER_DIFF_FIXTURES_1438_1453 = [
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
        default_test_lane: "dry-run"
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
        default_test_lane: "dry-run"
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
]
