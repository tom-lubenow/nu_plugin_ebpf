const VERIFIER_DIFF_FIXTURES_2285_2285 = [
    {
        name: "core-record-metadata-list-empty-predicates"
        category: "language-surface"
        tags: [core record columns values is-empty is-not-empty metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let empty_columns = ({} | columns | is-empty)'
            '  let empty_values = ({} | values | is-empty)'
            '  let filled_columns = ({ pid: 7, comm: "nu" } | columns | is-not-empty)'
            '  let filled_values = ({ pid: 7, comm: "nu" } | values | is-not-empty)'
            '  if $empty_columns and $empty_values and $filled_columns and $filled_values { 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
