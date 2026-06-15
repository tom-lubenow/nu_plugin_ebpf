export const VERIFIER_DIFF_FIXTURES_3834_3834 = [
    {
        name: "map-put-array-bool-sort-reverse-first"
        category: "maps"
        tags: [maps map-define map-put map-get arrays bool sort reverse first accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:2}" --max-entries 1'
            '  [false true] | map-put flags 0 --kind array'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    (($entry | sort --reverse | first) == true)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
