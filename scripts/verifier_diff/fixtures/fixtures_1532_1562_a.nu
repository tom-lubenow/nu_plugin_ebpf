const VERIFIER_DIFF_FIXTURES_1532_1562_A = [
    {
        name: "spin-lock-map-define-lock-unlock"
        category: "helper-state"
        tags: [spin-lock map-define accept]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "spin-lock-rejects-unreleased"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased bpf spin lock"
    }
    {
        name: "spin-lock-rejects-double-lock"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot be called while bpf_spin_lock is held"
    }
    {
        name: "spin-lock-rejects-unlock-of-different-map-entry"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let first = (0 | map-get locks --kind hash)'
            '  let second = (1 | map-get locks --kind hash)'
            '  if $first {'
            '    if $second {'
            '      helper-call "bpf_spin_lock" $first.lock'
            '      helper-call "bpf_spin_unlock" $second.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_spin_lock"
    }
    {
        name: "spin-lock-rejects-unlock-after-mixed-join"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '    }'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_spin_lock"
    }
    {
        name: "spin-lock-rejects-helper-while-held"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    helper-call "bpf_get_prandom_u32"'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot be called while bpf_spin_lock is held"
    }
    {
        name: "spin-lock-rejects-kfunc-while-held"
        category: "helper-state"
        tags: [spin-lock map-define kfunc reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot be called while bpf_spin_lock is held"
    }
    {
        name: "spin-lock-rejects-throw-while-held"
        category: "helper-state"
        tags: [spin-lock map-define kfunc throw reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    kfunc-call "bpf_throw" 1'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_throw' cannot be called while bpf_spin_lock is held"
    }
    {
        name: "spin-lock-map-define-rejects-lru-hash"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define locks --kind lru-hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bpf_spin_lock, which is only supported for hash and array maps"
    }
    {
        name: "spin-lock-map-define-rejects-array-field"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{locks:array{bpf_spin_lock:2},counter:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arrays of verifier-managed bpf_spin_lock"
    }
    {
        name: "timer-set-callback-rejects-non-map-timer"
        category: "helper-state"
        tags: [timer callback reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_timer_set_callback" 0 {|timer key val| 0}'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "timer-set-callback-rejects-dynamic-non-map-timer"
        category: "helper-state"
        tags: [timer callback dynamic branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers_dyn_set --kind hash --key-type u32 --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers_dyn_set --kind hash)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let timer = (if $selector == 0 { $entry.timer } else { 0 })'
            '    helper-call "bpf_timer_set_callback" $timer {|timer key val| 0}'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "timer-start-rejects-non-map-timer"
        category: "helper-state"
        tags: [timer reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{||'
            '  helper-call "bpf_timer_start" 0 1000 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "timer-start-rejects-dynamic-non-map-timer"
        category: "helper-state"
        tags: [timer dynamic branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers_dyn_start --kind hash --key-type u32 --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers_dyn_start --kind hash)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let timer = (if $selector == 0 { $entry.timer } else { 0 })'
            '    helper-call "bpf_timer_start" $timer 1000 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "timer-cancel-rejects-non-map-timer"
        category: "helper-state"
        tags: [timer reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_timer_cancel" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
]
