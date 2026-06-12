const VERIFIER_DIFF_FIXTURES_1454_1468 = [
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
        default_test_lane: "dry-run"
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
        default_test_lane: "dry-run"
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
        default_test_lane: "dry-run"
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
        default_test_lane: "dry-run"
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
]
