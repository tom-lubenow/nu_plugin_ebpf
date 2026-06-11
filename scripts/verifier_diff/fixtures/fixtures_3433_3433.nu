export const VERIFIER_DIFF_FIXTURES_3433_3433 = [
    {
        name: "map-get-array-bytes-length-sum"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes length math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    (($entry | bytes length | math sum) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
