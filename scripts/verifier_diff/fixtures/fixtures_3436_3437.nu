export const VERIFIER_DIFF_FIXTURES_3436_3437 = [
    {
        name: "map-get-array-bytes-index-of-list"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes index-of list get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    (($entry | bytes index-of 0x[00] | get 1) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bytes-index-of-end-list"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes index-of end list get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    (($entry | bytes index-of --end 0x[00] | get 0) == 3)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
