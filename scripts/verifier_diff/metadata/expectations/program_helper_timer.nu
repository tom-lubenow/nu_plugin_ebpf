const PROGRAM_TIMER_HELPER_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer timers 0 --kind array'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val| 0}'
            '    helper-call "bpf_timer_start" $entry.timer 1000 0'
            '    helper-call "bpf_timer_cancel" $entry.timer'
            '  }'
            '  0'
            '}'
        ]
        feature_keys: [
            "helper:bpf_timer_init"
            "helper:bpf_timer_set_callback"
            "helper:bpf_timer_start"
            "helper:bpf_timer_cancel"
        ]
    }
]
