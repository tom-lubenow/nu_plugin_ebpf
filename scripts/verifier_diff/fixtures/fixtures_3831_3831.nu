export const VERIFIER_DIFF_FIXTURES_3831_3831 = [
    {
        name: "map-get-array-bool-sort-first"
        category: "maps"
        tags: [maps map-define map-get arrays bool sort first accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:2}" --max-entries 1'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    (($entry | sort | first) == false)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
