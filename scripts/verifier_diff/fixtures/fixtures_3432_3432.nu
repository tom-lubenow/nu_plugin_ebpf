export const VERIFIER_DIFF_FIXTURES_3432_3432 = [
    {
        name: "map-get-array-string-str-length-sum"
        category: "maps"
        tags: [maps map-define map-get arrays string str length math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | str length | math sum) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
