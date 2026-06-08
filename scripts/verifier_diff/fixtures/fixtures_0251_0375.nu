const VERIFIER_DIFF_FIXTURES_0251_0375 = [
    {
        name: "constant-record-nested-list"
        category: "globals"
        tags: [globals records list accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let config = { pid: 7 samples: [11 22] }'
            '  (($config.samples | get 1) + $config.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-empty-binary-zero-fills"
        category: "globals"
        tags: [globals binary bytes global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[] | global-define --type bytes:8 scratch'
            '  let b = (global-get scratch)'
            '  ($b | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-empty-binary-field-zero-fills"
        category: "globals"
        tags: [globals records binary bytes global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: 0x[] } | global-define --type "record{pid:int,comm:bytes:4}" seen_state'
            '  let state = (global-get seen_state)'
            '  ($state.comm | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-length"
        category: "globals"
        tags: [globals binary bytes length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[] | global-define --type bytes:8 scratch'
            '  let b = (global-get scratch)'
            '  ($b | bytes length) == 8'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-length-command"
        category: "globals"
        tags: [globals binary length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[] | global-define --type bytes:8 scratch'
            '  let b = (global-get scratch)'
            '  ($b | length) == 8'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-is-empty"
        category: "globals"
        tags: [globals binary is-empty global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[] | global-define --type bytes:8 scratch'
            '  let b = (global-get scratch)'
            '  ($b | is-empty) == false'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-describe"
        category: "globals"
        tags: [globals binary describe global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type bytes:8 scratch'
            '  (global-get scratch) | describe | str starts-with "binary"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-bytes-field-length"
        category: "globals"
        tags: [globals records binary bytes length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: 0x[] } | global-define --type "record{pid:int,comm:bytes:4}" seen_state'
            '  let state = (global-get seen_state)'
            '  ($state.comm | bytes length) == 4'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-describe"
        category: "globals"
        tags: [globals arrays binary describe global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  (global-get buffers) | describe | str starts-with "list<binary>"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-bytes-length"
        category: "globals"
        tags: [globals arrays binary bytes length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  let lens = ((global-get buffers) | bytes length)'
            '  ($lens | get 1) == 4'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-first-length"
        category: "globals"
        tags: [globals arrays binary bytes first length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  ((global-get buffers) | first | bytes length) == 4'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-last"
        category: "globals"
        tags: [globals arrays first last global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  ((global-get ports) | last) == 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-take-length"
        category: "globals"
        tags: [globals arrays binary bytes take length get global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | take 1 | bytes length) | get 0) == 4'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-skip-length"
        category: "globals"
        tags: [globals arrays skip length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  ((global-get ports) | skip 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-drop-length"
        category: "globals"
        tags: [globals arrays drop length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  ((global-get ports) | drop 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-first-count-length"
        category: "globals"
        tags: [globals arrays first length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  ((global-get ports) | first 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-is-empty"
        category: "globals"
        tags: [globals arrays is-empty global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  ((global-get ports) | is-empty) == false'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-is-not-empty"
        category: "globals"
        tags: [globals arrays is-not-empty global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (global-get ports) | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-last-count-get"
        category: "globals"
        tags: [globals arrays get first last global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | last 1) | get 0) == 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bound-record-empty-binary-field-zero-fills"
        category: "globals"
        tags: [globals records binary bytes global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let state = { pid: 7 comm: 0x[] }'
            '  $state | global-define --type "record{pid:int,comm:bytes:4}" seen_state'
            '  let state = (global-get seen_state)'
            '  ($state.comm | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-string-concat-initializer"
        category: "globals"
        tags: [globals string global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let greeting = ("hel" + "lo")'
            '  $greeting | global-define --type string:8 greeting'
            '  let stored = (global-get greeting)'
            '  ($stored | str length) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-runtime-string-concat"
        category: "globals"
        tags: [globals string global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  let greeting = ($left + "lo")'
            '  $greeting | str length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-runtime-string-equality"
        category: "globals"
        tags: [globals string global-define equality accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "lo" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left == "lo"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-builder-initializer"
        category: "globals"
        tags: [globals records global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let state = ({} | insert pid 7)'
            '  $state | global-define --type "record{pid:int}" state'
            '  let stored = (global-get state)'
            '  $stored.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bool-not-initializer"
        category: "globals"
        tags: [globals scalar bool global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let enabled = (not false)'
            '  $enabled | global-define --type bool enabled'
            '  let stored = (global-get enabled)'
            '  if $stored { 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-int-add-initializer"
        category: "globals"
        tags: [globals scalar global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let sum = (3 + 4)'
            '  $sum | global-define --type int sum'
            '  let stored = (global-get sum)'
            '  $stored | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-int-record-field-initializer"
        category: "globals"
        tags: [globals records scalar global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let state = { pid: 7 }'
            '  $state.pid | global-define --type int seen_pid'
            '  let stored = (global-get seen_pid)'
            '  $stored | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-int-bool-initializer-rejects"
        category: "globals"
        tags: [globals scalar bool global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  true | global-define --type int state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'int' initializer requires a i64-compatible constant"
    }
    {
        name: "global-define-type-list-int-initializer"
        category: "globals"
        tags: [globals list global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [11 22] | global-define --type "list:int:4" samples'
            '  let samples = (global-get samples)'
            '  ($samples | get 1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-list-int-bool-item-rejects"
        category: "globals"
        tags: [globals list bool global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [true] | global-define --type "list:int:4" samples'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'list:int:4' initializer[0] requires a numeric constant item, found bool"
    }
    {
        name: "global-define-type-bound-list-int-initializer"
        category: "globals"
        tags: [globals list global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let initial = [11 22]'
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
    {
        name: "global-define-type-nested-record-malformed-field-rejects-path"
        category: "globals"
        tags: [globals records diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{inner:record{bad}}" seen_state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'inner.bad' must use name:type syntax"
    }
    {
        name: "global-define-type-nested-record-invalid-array-length-rejects-path"
        category: "globals"
        tags: [globals records arrays diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{items:array{u32:x}}" seen_state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'items' type spec 'array{u32:x}' has an invalid array length"
    }
    {
        name: "global-define-type-record-unmatched-braces-rejects-candidate"
        category: "globals"
        tags: [globals records diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{inner:record{pid:u32" seen_state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'record{inner:record{pid:u32' has unmatched '{' braces"
    }
    {
        name: "global-define-type-record-partial-list-field-zero-fills"
        category: "globals"
        tags: [globals records list global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 } | global-define --type "record{pid:int,samples:list:int:2}" seen_state'
            '  let state = (global-get seen_state)'
            '  (($state.samples | length) + $state.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-zero-record-list-field-get"
        category: "globals"
        tags: [globals records list global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,samples:list:int:2}" seen_state'
            '  let state = (global-get seen_state)'
            '  (($state.samples | get 1) + $state.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-zero-nested-record-list-field-get"
        category: "globals"
        tags: [globals records list nested global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{inner:record{pid:int,samples:list:int:2},cpu:u32}" seen_state'
            '  let state = (global-get seen_state)'
            '  (($state.inner.samples | get 1) + $state.inner.pid + $state.cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-zero-record-list-field-append"
        category: "globals"
        tags: [globals records list upsert global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{samples:list:int:2}" seen_state'
            '  mut state = (global-get seen_state)'
            '  $state.samples.0 = 11'
            '  $state.samples.0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-array-field-initializer"
        category: "globals"
        tags: [globals records arrays global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 ports: [11 22] } | global-define --type "record{ports:array{u16:4},pid:int}" seen_state'
            '  let state = (global-get seen_state)'
            '  ($state.ports | get 1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-array-record-field-initializer"
        category: "globals"
        tags: [globals records arrays global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { entries: [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] } | global-define --type "record{entries:array{record{pid:int,cpu:u32}:2}}" seen_state'
            '  let state = (global-get seen_state)'
            '  (($state.entries | get 1).cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-initializer"
        category: "globals"
        tags: [globals records arrays global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | global-define --type "array{record{pid:int,cpu:u32}:2}" seen_entries'
            '  let entries = (global-get seen_entries)'
            '  (($entries | get 1).cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-list-builder-initializer"
        category: "globals"
        tags: [globals records arrays append global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entries = ([] | append { pid: 7 cpu: 2 } | append { pid: 9 cpu: 3 })'
            '  $entries | global-define --type "array{record{pid:int,cpu:u32}:2}" seen_entries'
            '  let entries = (global-get seen_entries)'
            '  (($entries | get 1).cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-nested-numeric-list-upsert"
        category: "globals"
        tags: [globals records arrays list upsert global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{samples: [1 2]} {samples: [3 4]}] | global-define --type "array{record{samples:list:int:2}:2}" entries'
            '  mut entries = (global-get entries)'
            '  $entries.1.samples.1 = 9'
            '  $entries.1.samples.1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-nested-string-field"
        category: "globals"
        tags: [globals records arrays string global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{name: "aa"} {name: "bb"}] | global-define --type "array{record{name:string:15}:2}" entries'
            '  let entries = (global-get entries)'
            '  $entries.1.name | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-nested-string-upsert"
        category: "globals"
        tags: [globals records arrays string upsert global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{name: "aa"} {name: "bb"}] | global-define --type "array{record{name:string:15}:2}" entries'
            '  mut entries = (global-get entries)'
            '  $entries.1.name = "cc"'
            '  $entries.1.name | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-spread-initializer"
        category: "globals"
        tags: [globals records arrays list-spread global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let tail = [{ pid: 9 cpu: 3 }]'
            '  [{ pid: 7 cpu: 2 }, ...$tail] | global-define --type "array{record{pid:int,cpu:u32}:2}" seen_entries'
            '  let entries = (global-get seen_entries)'
            '  (($entries | get 1).cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-array-record-initializer"
        category: "globals"
        tags: [globals records arrays global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | global-set seen_entries'
            '  let entries = (global-get seen_entries)'
            '  (($entries | get 1).cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-array-record-list-builder-initializer"
        category: "globals"
        tags: [globals records arrays append global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entries = ([] | append { pid: 7 cpu: 2 } | append { pid: 9 cpu: 3 })'
            '  $entries | global-set seen_entries'
            '  let entries = (global-get seen_entries)'
            '  (($entries | get 1).cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-array-record-spread-initializer"
        category: "globals"
        tags: [globals records arrays list-spread global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let tail = [{ pid: 9 cpu: 3 }]'
            '  [{ pid: 7 cpu: 2 }, ...$tail] | global-set seen_entries'
            '  let entries = (global-get seen_entries)'
            '  (($entries | get 1).cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-set-record-array-record-field-initializer"
        category: "globals"
        tags: [globals records arrays global-set accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { entries: [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] } | global-set seen_state'
            '  let state = (global-get seen_state)'
            '  (($state.entries | get 1).cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-empty-binary-without-type-rejects"
        category: "globals"
        tags: [globals binary global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[] | global-define scratch'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "empty binary constants do not establish a fixed byte-buffer layout"
    }
    {
        name: "global-define-record-empty-binary-field-without-type-rejects"
        category: "globals"
        tags: [globals records binary global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 meta: { comm: 0x[] } } | global-define scratch'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'meta.comm'"
    }
    {
        name: "map-define-null-only-lookup-keeps-value-layout"
        category: "maps"
        tags: [maps map-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define null_only --kind hash --value-type int'
            '  42 | map-put null_only 0 --kind hash'
            '  let entry = (0 | map-get null_only --kind hash)'
            '  if $entry { 0 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-max-entries"
        category: "maps"
        tags: [maps map-define max-entries accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define small_seen --kind hash --value-type int --max-entries 32'
            '  42 | map-put small_seen 0 --kind hash'
            '  let entry = (0 | map-get small_seen --kind hash)'
            '  if $entry { $entry | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-inferred-array-kind"
        category: "maps"
        tags: [maps map-define kind-inference accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define array_slots --kind array --value-type int --max-entries 32'
            '  42 | map-put array_slots 0'
            '  let entry = (0 | map-get array_slots)'
            '  if $entry { $entry | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-same-name-conflicting-kinds-rejects"
        category: "maps"
        tags: [maps kind-conflict reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  42 | map-put shared_resource 0 --kind array'
            '  let entry = (0 | map-get shared_resource --kind hash)'
            '  if $entry { $entry | count }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "conflicts with prior map kind"
    }
    {
        name: "map-operation-inferred-array-kind"
        category: "maps"
        tags: [maps kind-inference accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  42 | map-put operation_slots 0 --kind array'
            '  let entry = (0 | map-get operation_slots)'
            '  if $entry { $entry | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-map-in-map-inner-template-object"
        category: "maps"
        tags: [maps map-define map-in-map accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  map-define outer_hash --kind hash-of-maps --key-type u32 --inner-map inner_seen --max-entries 4'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-map-in-map-operation-accepts"
        category: "maps"
        tags: [maps map-define map-in-map accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  let entry = (0 | map-get outer_array --kind array-of-maps)'
            '  if $entry { 1 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-map-in-map-inferred-operation-accepts"
        category: "maps"
        tags: [maps map-define map-in-map kind-inference accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  let entry = (0 | map-get outer_array)'
            '  if $entry { 1 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-map-in-map-dynamic-inner-lookup-accepts"
        category: "maps"
        tags: [maps map-define map-in-map dynamic-lookup accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  let inner = (0 | map-get outer_array)'
            '  if $inner {'
            '    let value = (7 | map-get $inner)'
            '    if $value { $value | count }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-map-in-map-dynamic-inner-update-delete-accepts"
        category: "maps"
        tags: [maps map-define map-in-map dynamic-update dynamic-delete accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type int --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  let outer_present = (0 | map-contains outer_array)'
            '  if $outer_present { 1 }'
            '  let inner = (0 | map-get outer_array)'
            '  if $inner {'
            '    99 | map-put $inner 7'
            '    let inner_present = (7 | map-contains $inner)'
            '    if $inner_present { 1 }'
            '    7 | map-delete $inner'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-hash-of-maps-operation-accepts"
        category: "maps"
        tags: [maps map-define map-in-map accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_hash --kind hash-of-maps --key-type u32 --inner-map inner_seen --max-entries 4'
            '  let entry = (0 | map-get outer_hash --kind hash-of-maps)'
            '  if $entry { 1 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-hash-of-maps-inferred-operation-accepts"
        category: "maps"
        tags: [maps map-define map-in-map kind-inference accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_hash --kind hash-of-maps --key-type u32 --inner-map inner_seen --max-entries 4'
            '  let entry = (0 | map-get outer_hash)'
            '  if $entry { 1 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-map-in-map-rejects-missing-inner-map"
        category: "maps"
        tags: [maps map-define map-in-map reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define outer_array --kind array-of-maps --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires --inner-map"
    }
    {
        name: "map-define-map-in-map-rejects-self-inner-map"
        category: "maps"
        tags: [maps map-define map-in-map reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define outer_array --kind array-of-maps --inner-map outer_array --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use itself as its inner map template"
    }
    {
        name: "map-define-map-in-map-rejects-nested-inner-template"
        category: "maps"
        tags: [maps map-define map-in-map reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define leaf_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define inner_outer --kind array-of-maps --inner-map leaf_seen --max-entries 4'
            '  map-define outer_array --kind array-of-maps --inner-map inner_outer --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "must name a previously declared inner map with --value-type"
    }
    {
        name: "map-define-map-in-map-rejects-outer-value-type"
        category: "maps"
        tags: [maps map-define map-in-map reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --value-type u64 --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "--value-type is not supported for map-in-map outer map"
    }
    {
        name: "map-define-hash-of-maps-rejects-missing-key-type"
        category: "maps"
        tags: [maps map-define map-in-map reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_hash --kind hash-of-maps --inner-map inner_seen --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "hash-of-maps requires --key-type"
    }
    {
        name: "queue-map-push-peek-record"
        category: "maps"
        tags: [maps queue map-push map-peek records accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: $ctx.arg0, cookie: 7 } | map-push recent_args --kind queue'
            '  let entry = (map-peek recent_args --kind queue)'
            '  if $entry {'
            '    $entry.pid | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "stack-map-push-pop-record"
        category: "maps"
        tags: [maps stack map-push map-pop records accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: $ctx.arg0, cookie: 7 } | map-push recent_args --kind stack'
            '  let entry = (map-pop recent_args --kind stack)'
            '  if $entry {'
            '    $entry.cookie | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-map-update-delete-helpers"
        category: "maps"
        tags: [maps helper-call map-update map-delete accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_update_elem" seen $key $value 0'
            '  helper-call "bpf_map_delete_elem" seen $key'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-map-update-rejects-invalid-flags"
        category: "maps"
        tags: [maps helper-call map-update flags reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_update_elem" seen $key $value 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_map_update_elem' requires arg3 flags"
    }
    {
        name: "raw-map-update-rejects-dynamic-flags"
        category: "maps"
        tags: [maps helper-call map-update flags reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  let value = "abcdefgh"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_map_update_elem" seen $key $value $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_map_update_elem' requires arg3 flags"
    }
    {
        name: "raw-queue-map-push-peek-pop-helpers"
        category: "maps"
        tags: [maps queue helper-call map-push map-peek map-pop accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_push_elem" recent_raw $value 0 --kind queue'
            '  helper-call "bpf_map_peek_elem" recent_raw $value --kind queue'
            '  helper-call "bpf_map_pop_elem" recent_raw $value --kind queue'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-queue-map-push-rejects-invalid-flags"
        category: "maps"
        tags: [maps queue helper-call map-push flags reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_push_elem" recent_raw $value 4 --kind queue'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_map_push_elem' requires arg2 flags"
    }
    {
        name: "raw-queue-map-push-rejects-dynamic-flags"
        category: "maps"
        tags: [maps queue helper-call map-push flags reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_map_push_elem" recent_raw $value $flags --kind queue'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_map_push_elem' requires arg2 flags"
    }
    {
        name: "bloom-filter-push-contains"
        category: "maps"
        tags: [maps bloom-filter map-push map-contains accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-push seen_args --kind bloom-filter'
            '  $ctx.arg0 | map-contains seen_args --kind bloom-filter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "per-cpu-hash-map-put-get"
        category: "maps"
        tags: [maps per-cpu-hash map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put cpu_seen 0 --kind per-cpu-hash'
            '  let entry = (0 | map-get cpu_seen --kind per-cpu-hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lru-per-cpu-hash-map-put-delete"
        category: "maps"
        tags: [maps lru-per-cpu-hash map-put map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put lru_cpu_seen 0 --kind lru-per-cpu-hash'
            '  0 | map-delete lru_cpu_seen --kind lru-per-cpu-hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "task-storage-map-get-init"
        category: "maps"
        tags: [maps local-storage task-storage map-get accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let state = ($ctx.task | map-get task_state --kind task-storage --init { hits: 0 })'
            '  if $state {'
            '    $state.hits | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "task-storage-map-delete"
        category: "maps"
        tags: [maps local-storage task-storage map-delete accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-delete task_state --kind task-storage'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "task-storage-map-contains"
        category: "maps"
        tags: [maps local-storage task-storage map-contains accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  if ($ctx.task | map-contains task_state --kind task-storage) {'
            '    1 | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-storage-map-contains"
        category: "maps"
        tags: [maps local-storage sk-storage map-contains accept]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  $ctx.sk | map-contains sock_state --kind sk-storage'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-storage-map-get-init"
        category: "maps"
        tags: [maps local-storage sk-storage map-get accept]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  let state = ($ctx.sk | map-get sock_state --kind sk-storage --init { hits: 0 })'
            '  if $state {'
            '    $state.hits | count'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-storage-map-delete"
        category: "maps"
        tags: [maps local-storage sk-storage map-delete accept]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk {'
            '    $sk | map-delete sock_state --kind sk-storage'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "inode-storage-map-delete"
        category: "maps"
        tags: [maps local-storage inode-storage map-delete accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_inode | map-delete inode_state --kind inode-storage'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "inode-storage-map-get-init"
        category: "maps"
        tags: [maps local-storage inode-storage map-get accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let state = ($ctx.arg.file.f_inode | map-get inode_state --kind inode-storage --init { hits: 0 })'
            '  if $state {'
            '    $state.hits | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgrp-storage-map-contains"
        category: "maps"
        tags: [maps local-storage cgrp-storage map-contains accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-contains cgrp_state --kind cgrp-storage'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgrp-storage-map-get-init"
        category: "maps"
        tags: [maps local-storage cgrp-storage map-get accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let state = ($ctx.current_cgroup | map-get cgrp_state --kind cgrp-storage --init { hits: 0 })'
            '  if $state {'
            '    $state.hits | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgrp-storage-map-delete"
        category: "maps"
        tags: [maps local-storage cgrp-storage map-delete accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-delete cgrp_state --kind cgrp-storage'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-sk-storage-get-helper"
        category: "maps"
        tags: [maps local-storage sk-storage helper-call accept source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  helper-call "bpf_sk_storage_get" sock_state $ctx.sk 0 0'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-task-storage-get-helper"
        category: "maps"
        tags: [maps local-storage task-storage helper-call accept source metadata]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_task_storage_get" task_state $ctx.task 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-inode-storage-get-helper"
        category: "maps"
        tags: [maps local-storage inode-storage helper-call accept source metadata]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_inode_storage_get" inode_state $ctx.arg.file.f_inode 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
