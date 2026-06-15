const VERIFIER_DIFF_FIXTURES_0282_0312_B = [
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
]
