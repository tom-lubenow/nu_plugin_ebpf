export const VERIFIER_DIFF_FIXTURES_3844_3844 = [
    {
        name: "map-get-array-bool-compact-length"
        category: "maps"
        tags: [maps map-define map-get arrays bool compact length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:2}" --max-entries 1'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    (($entry | compact | length) == 2)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
