export const VERIFIER_DIFF_FIXTURES_3840_3840 = [
    {
        name: "map-get-array-bool-is-not-empty"
        category: "maps"
        tags: [maps map-define map-get arrays bool is-not-empty accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:2}" --max-entries 1'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    $entry | is-not-empty'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
