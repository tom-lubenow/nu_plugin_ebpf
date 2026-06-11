export const VERIFIER_DIFF_FIXTURES_3712_3712 = [
    {
        name: "bpf-wq-set-callback-record-string-key-field-length"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback map-define records string key-type str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define wq_key_names --kind hash --key-type "record{name:string:15,id:u32}" --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  { name: "aa" id: 7 } | global-define --type "record{name:string:15,id:u32}" wq_name_key'
            '  let lookup_key = (global-get wq_name_key)'
            '  let entry = ($lookup_key | map-get wq_key_names --kind hash)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work wq_key_names 0'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key work|'
            '      ($key.name | str length) | count'
            '      0'
            '    } 0 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
