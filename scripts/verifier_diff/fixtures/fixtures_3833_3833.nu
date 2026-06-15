export const VERIFIER_DIFF_FIXTURES_3833_3833 = [
    {
        name: "map-get-array-bool-reverse-first"
        category: "maps"
        tags: [maps map-define map-get arrays bool reverse first accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:2}" --max-entries 1'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    (($entry | reverse | first) == false)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
