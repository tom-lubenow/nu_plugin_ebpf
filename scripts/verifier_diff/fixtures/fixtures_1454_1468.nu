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
]
