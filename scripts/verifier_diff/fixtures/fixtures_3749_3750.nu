export const VERIFIER_DIFF_FIXTURES_3749_3750 = [
    {
        name: "map-get-array-bool-find-false-length"
        category: "maps"
        tags: [maps map-define map-get arrays bool find length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:2}" --max-entries 1'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    (($entry | find false | length) == 2)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bool-uniq-length"
        category: "maps"
        tags: [maps map-define map-get arrays bool uniq length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:2}" --max-entries 1'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    (($entry | uniq | length) == 1)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
