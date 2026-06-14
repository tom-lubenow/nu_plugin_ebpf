const VERIFIER_DIFF_FIXTURES_3098_3098 = [
    {
        name: "core-record-transpose-as-record"
        category: "records"
        tags: [records transpose as-record accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | transpose --as-record | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-transpose-as-record-length-variants"
        category: "records"
        tags: [records transpose as-record ignore-titles length accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let default_len = ({pid: 1 cpu: 2} | transpose --as-record | length)'
            '  let custom_len = ({pid: 1 cpu: 2} | transpose --as-record key value | length)'
            '  let ignored_len = ({pid: 1 cpu: 2} | transpose --as-record --ignore-titles val | length)'
            '  ($default_len == 2) and (($custom_len == 2) and ($ignored_len == 1))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
