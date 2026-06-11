const PROGRAM_HELPER_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  let text = "helper-call \"bpf_trace_printk\" \"ignored\" 7"'
            '  # helper-call "bpf_map_lookup_elem" ignored key'
            '  let ignored = 0 # | helper-call "bpf_ktime_get_ns"'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  let arg0 = "01234567"'
            '  let retval = "01234567"'
            '  (helper-call "bpf_get_func_arg" $ctx 0 $arg0) | count'
            '  (helper-call "bpf_get_func_ret" $ctx $retval) | count'
            '  (helper-call "bpf_get_func_arg_cnt" $ctx) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "helper:bpf_get_func_arg"
            "helper:bpf_get_func_ret"
            "helper:bpf_get_func_arg_cnt"
        ]
    }
    {
        program: [
            '{|ctx|'
            '  map-define nsdata --kind array --value-type bytes:8 --max-entries 1'
            '  let ns = (0 | map-get nsdata)'
            '  if $ns {'
            '    helper-call "bpf_get_ns_current_pid_tgid" 0 0 $ns 8'
            '  }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_get_ns_current_pid_tgid"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_cgroup_classid" $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_skb_cgroup_classid"]
    }
    {
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_fib_lookup"]
    }
    {
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_check_mtu"]
    }
    {
        program: [
            '{|ctx|'
            '  let key = "01234567"'
            '  helper-call "bpf_map_lookup_percpu_elem" per_cpu_values $key 0 --kind per-cpu-array'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_map_lookup_percpu_elem"]
    }
    {
        program: [
            '{|ctx|'
            '  let tuple = "0123456789abcdef"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 16 0 0)'
            '  if $sk {'
            '    helper-call "bpf_sk_release" $sk'
            '  }'
            '  "pass"'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_lookup_tcp" "helper:bpf_sk_release"]
    }
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
