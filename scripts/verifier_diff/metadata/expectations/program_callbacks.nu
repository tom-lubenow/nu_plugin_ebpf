const PROGRAM_CALLBACK_BTF_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val|'
            '      $timer.id | count'
            '      0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    $m.id | count'
            '    0'
            '  } "ctx" 0 --kind array'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_find_vma" $ctx.current_task 0 {|task vma cb|'
            '    $vma.vm_start | count'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        feature_keys: []
    }
]
