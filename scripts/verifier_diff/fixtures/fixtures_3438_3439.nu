export const VERIFIER_DIFF_FIXTURES_3438_3439 = [
    {
        name: "map-get-array-bytes-collect-length"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes collect length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    (($entry | bytes collect | bytes length) == 8)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bytes-reverse-collect-length"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes reverse collect length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    (($entry | bytes reverse | bytes collect | bytes length) == 8)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
