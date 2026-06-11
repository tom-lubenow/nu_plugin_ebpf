export const VERIFIER_DIFF_FIXTURES_3434_3435 = [
    {
        name: "map-get-array-bytes-starts-with-bool-list"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes starts-with bool-list get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    (($entry | bytes starts-with 0x[00] | get 1) == 1)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bytes-ends-with-bool-list"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes ends-with bool-list get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    (($entry | bytes ends-with 0x[00] | get 0) == 1)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
