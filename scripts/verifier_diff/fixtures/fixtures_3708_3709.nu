export const VERIFIER_DIFF_FIXTURES_3708_3709 = [
    {
        name: "timer-callback-value-record-string-field-length"
        category: "helper-state"
        tags: [timer callback map-define records string str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers_names --kind array --value-type "record{timer:bpf_timer,name:string:15}" --max-entries 1'
            '  let entry = (0 | map-get timers_names --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val|'
            '      ($val.name | str length) | count'
            '      0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "timer-callback-value-record-list-field-get"
        category: "helper-state"
        tags: [timer callback map-define records list get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers_samples --kind array --value-type "record{timer:bpf_timer,samples:list:int:2}" --max-entries 1'
            '  let entry = (0 | map-get timers_samples --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val|'
            '      ($val.samples | get 1) | count'
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
