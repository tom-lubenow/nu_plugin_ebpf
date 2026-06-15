export const VERIFIER_DIFF_FIXTURES_3839_3839 = [
    {
        name: "map-get-array-bool-is-empty"
        category: "maps"
        tags: [maps map-define map-get arrays bool is-empty accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:2}" --max-entries 1'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    (($entry | is-empty) == false)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
