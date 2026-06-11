export const VERIFIER_DIFF_FIXTURES_3713_3715 = [
    {
        name: "core-record-get-optional-missing-field"
        category: "records"
        tags: [records get optional missing accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | get --optional uid | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-select-optional-missing-field"
        category: "records"
        tags: [records select optional missing columns accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1} | select --optional uid | get --optional uid | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-reject-optional-missing-field"
        category: "records"
        tags: [records reject-cmd optional missing accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {pid: 1 cpu: 2} | reject --optional uid | get cpu'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
