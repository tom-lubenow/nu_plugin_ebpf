const VERIFIER_DIFF_FIXTURES_1188_1218_B = [
    {
        name: "source-kfunc-iter-task-vma-rejects-double-destroy"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_task_vma_new" $iter $ctx.current_task 0'
            '  kfunc-call "bpf_iter_task_vma_destroy" $iter'
            '  kfunc-call "bpf_iter_task_vma_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_task_vma_destroy' requires a matching bpf_iter_task_vma_new"
    }
    {
        name: "source-kfunc-iter-css-lifecycle-balanced"
        category: "helper-state"
        tags: [kfunc iter cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    kfunc-call "bpf_iter_css_new" $iter $cgrp 0'
            '    let css = (kfunc-call "bpf_iter_css_next" $iter)'
            '    if $css { 0 }'
            '    kfunc-call "bpf_iter_css_destroy" $iter'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-css-rejects-next-without-new"
        category: "helper-state"
        tags: [kfunc iter cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_css_next" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_css_next' requires a matching bpf_iter_css_new"
    }
    {
        name: "source-kfunc-iter-css-rejects-leak"
        category: "helper-state"
        tags: [kfunc iter cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    kfunc-call "bpf_iter_css_new" $iter $cgrp 0'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased iter_css iterator"
    }
    {
        name: "source-kfunc-iter-css-rejects-double-destroy"
        category: "helper-state"
        tags: [kfunc iter cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    kfunc-call "bpf_iter_css_new" $iter $cgrp 0'
            '    kfunc-call "bpf_iter_css_destroy" $iter'
            '    kfunc-call "bpf_iter_css_destroy" $iter'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_css_destroy' requires a matching bpf_iter_css_new"
    }
    {
        name: "source-kfunc-iter-css-task-lifecycle-balanced"
        category: "helper-state"
        tags: [kfunc iter cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    kfunc-call "bpf_iter_css_task_new" $iter $cgrp 0'
            '    let task = (kfunc-call "bpf_iter_css_task_next" $iter)'
            '    if $task { 0 }'
            '    kfunc-call "bpf_iter_css_task_destroy" $iter'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-css-task-rejects-next-without-new"
        category: "helper-state"
        tags: [kfunc iter cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_css_task_next" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_css_task_next' requires a matching bpf_iter_css_task_new"
    }
    {
        name: "source-kfunc-iter-css-task-rejects-leak"
        category: "helper-state"
        tags: [kfunc iter cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    kfunc-call "bpf_iter_css_task_new" $iter $cgrp 0'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased iter_css_task iterator"
    }
]
