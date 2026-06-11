export const VERIFIER_DIFF_FIXTURES_3710_3711 = [
    {
        name: "callback-for-each-map-elem-record-string-key-field-length"
        category: "callbacks"
        tags: [helper-call callback map hash records string key-type str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define callback_key_names --kind hash --key-type "record{name:string:15,id:u32}" --value-type u64'
            '  helper-call "bpf_for_each_map_elem" callback_key_names {|m k v cb|'
            '    ($k.name | str length) | count'
            '    0'
            '  } "ctx" 0 --kind hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "timer-callback-record-list-key-field-get"
        category: "helper-state"
        tags: [timer callback map-define records list key-type get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers_key_samples --kind hash --key-type "record{samples:list:int:2,id:u32}" --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  { samples: [1 2] id: 7 } | global-define --type "record{samples:list:int:2,id:u32}" timer_sample_key'
            '  let lookup_key = (global-get timer_sample_key)'
            '  let entry = ($lookup_key | map-get timers_key_samples --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val|'
            '      ($key.samples | get 1) | count'
            '      0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
