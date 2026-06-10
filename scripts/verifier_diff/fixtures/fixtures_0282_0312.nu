const VERIFIER_DIFF_FIXTURES_0282_0312 = [
    {
        name: "global-define-type-list-builder-initializer"
        category: "globals"
        tags: [globals list append global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let initial = ([] | append 11 | append 22)'
            '  $initial | global-define --type "list:int:4" samples'
            '  let samples = (global-get samples)'
            '  ($samples | get 1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-get-before-later-global-define-data"
        category: "globals"
        tags: [globals scalar forward global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let before = (global-get state)'
            '  7 | global-define state'
            '  $before | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-get-before-later-typed-global-define-bss"
        category: "globals"
        tags: [globals scalar typed forward global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let before = (global-get state)'
            '  global-define --type int state'
            '  $before | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-get-before-later-typed-record-global-define-bss"
        category: "globals"
        tags: [globals records typed forward global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let before = (global-get state)'
            '  global-define --type "record{pid:int}" state'
            '  $before.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-get-before-later-typed-record-global-define-data"
        category: "globals"
        tags: [globals records typed forward upsert global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut seed = { pid: 0 }'
            '  $seed.pid = 8'
            '  let before = (global-get state)'
            '  $seed | global-define --type "record{pid:int}" state'
            '  $before.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-zero-list-root-appends"
        category: "globals"
        tags: [globals list upsert global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "list:int:2" samples'
            '  mut samples = (global-get samples)'
            '  $samples.0 = 11'
            '  $samples.1 = 22'
            '  $samples.1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-initialized-list-root-append"
        category: "globals"
        tags: [globals list upsert global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [11 22] | global-define --type "list:int:4" samples'
            '  mut samples = (global-get samples)'
            '  $samples.2 = 33'
            '  $samples.2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-root-list-append-past-capacity-rejects"
        category: "globals"
        tags: [globals list upsert global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [11] | global-define --type "list:int:1" samples'
            '  mut samples = (global-get samples)'
            '  $samples.1 = 22'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot append beyond numeric list capacity 1"
    }
    {
        name: "global-set-mutated-root-numeric-list"
        category: "globals"
        tags: [globals list upsert global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "list:int:2" samples'
            '  mut samples = (global-get samples)'
            '  $samples.0 = 11'
            '  $samples | global-set samples'
            '  let persisted = (global-get samples)'
            '  $persisted.0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-get-before-later-global-set-bss"
        category: "globals"
        tags: [globals scalar forward global-set zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let before = (global-get state)'
            '  7 | global-set state'
            '  $before | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-root-scalar-data"
        category: "globals"
        tags: [globals scalar global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  7 | global-set seen_pid'
            '  let pid = (global-get seen_pid)'
            '  $pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-root-scalar-bss"
        category: "globals"
        tags: [globals scalar zero-fill global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | global-set seen_zero'
            '  let value = (global-get seen_zero)'
            '  $value | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-root-string-field-get"
        category: "globals"
        tags: [globals string global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "hello" | global-set seen_name'
            '  let name = (global-get seen_name)'
            '  ($name | str length) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-root-binary-get"
        category: "globals"
        tags: [globals binary bytes global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | global-set scratch'
            '  let b = (global-get scratch)'
            '  ($b | get 1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-runtime-record-list-field-get"
        category: "globals"
        tags: [globals records list global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,samples:list:int:2}" src_state'
            '  let src = (global-get src_state)'
            '  $src | global-set dst_state'
            '  let dst = (global-get dst_state)'
            '  (($dst.samples | get 1) + $dst.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-runtime-record-string-field-get"
        category: "globals"
        tags: [globals records string global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{msg:string:15,pid:int}" src_state'
            '  let src = (global-get src_state)'
            '  $src | global-set dst_state'
            '  let dst = (global-get dst_state)'
            '  (($dst.msg | str length) + $dst.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-metadata-record-string-field-get"
        category: "globals"
        tags: [globals records string global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { msg: "hi" pid: 7 } | global-set seen_state'
            '  let state = (global-get seen_state)'
            '  (($state.msg | str length) + $state.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-record-builder-string-field-get"
        category: "globals"
        tags: [globals records string insert global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let state = ({} | insert msg "hi" | insert pid 7)'
            '  $state | global-set seen_state'
            '  let state = (global-get seen_state)'
            '  (($state.msg | str length) + $state.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-metadata-record-list-field-get"
        category: "globals"
        tags: [globals records list global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { vals: [11 22] pid: 7 } | global-set seen_state'
            '  let state = (global-get seen_state)'
            '  (($state.vals | get 1) + $state.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-nested-record-builder-list-field-get"
        category: "globals"
        tags: [globals records list nested insert global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let inner = ({} | insert vals [11 22] | insert pid 7)'
            '  let state = ({} | insert inner $inner | insert cpu 1)'
            '  $state | global-set seen_state'
            '  let state = (global-get seen_state)'
            '  (($state.inner.vals | get 1) + $state.inner.pid + $state.cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-nested-metadata-record-list-field-get"
        category: "globals"
        tags: [globals records list nested global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let inner = { pid: 7 vals: [11 22] }'
            '  { inner: $inner cpu: 1 } | global-set seen_state'
            '  let state = (global-get seen_state)'
            '  (($state.inner.vals | get 1) + $state.inner.pid + $state.cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-nested-metadata-record-string-field-get"
        category: "globals"
        tags: [globals records string nested global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let inner = { pid: 7 msg: "hi" }'
            '  { inner: $inner cpu: 1 } | global-set seen_state'
            '  let state = (global-get seen_state)'
            '  (($state.inner.msg | str length) + $state.inner.pid + $state.cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-initializer"
        category: "globals"
        tags: [globals arrays global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [11 22] | global-define --type "array{u32:4}" ports'
            '  let ports = (global-get ports)'
            '  ($ports | get 1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bound-array-u32-initializer"
        category: "globals"
        tags: [globals arrays global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let initial = [11 22]'
            '  $initial | global-define --type "array{u32:4}" ports'
            '  let ports = (global-get ports)'
            '  ($ports | get 1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bool-initializer"
        category: "globals"
        tags: [globals arrays bool global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [true false] | global-define --type "array{bool:4}" flags'
            '  let flags = (global-get flags)'
            '  if ($flags | get 0) { 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-initializer"
        category: "globals"
        tags: [globals arrays binary global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04 05]] | global-define --type "array{bytes:4:2}" buffers'
            '  let buffers = (global-get buffers)'
            '  ($buffers | get 1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-initializer"
        category: "globals"
        tags: [globals arrays string global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["aa" "bb"] | global-define --type "array{string:8:2}" names'
            '  let names = (global-get names)'
            '  ($names | get 1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-list-int-initializer"
        category: "globals"
        tags: [globals arrays list global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [[11 22] [33 44]] | global-define --type "array{list:int:4:2}" sample_sets'
            '  let sample_sets = (global-get sample_sets)'
            '  (($sample_sets | get 1) | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bad-item-rejects-index"
        category: "globals"
        tags: [globals arrays diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [true] | global-define --type "array{u32:2}" ports'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "initializer[0] requires a u32-compatible constant"
    }
    {
        name: "global-define-type-record-list-field-initializer"
        category: "globals"
        tags: [globals records list global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 samples: [11 22] } | global-define --type "record{pid:int,samples:list:int:4}" seen_state'
            '  let state = (global-get seen_state)'
            '  ($state.samples | get 1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-nested-record-extra-field-rejects-path"
        category: "globals"
        tags: [globals records diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { inner: { pid: 7 extra: true } } | global-define --type "record{inner:record{pid:int}}" seen_state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unexpected field 'inner.extra'"
    }
]
