const VERIFIER_DIFF_FIXTURES_1469_1500 = [
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
