export const VERIFIER_DIFF_FIXTURES_3775_3777 = [
    {
        name: "map-get-array-bytes-each-starts-with-sum"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes each closure starts-with math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    (($entry | each {|x| ($x | bytes starts-with 0x[00]) } | math sum) == 2)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bytes-each-ends-with-sum"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes each closure ends-with math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    (($entry | each {|x| ($x | bytes ends-with 0x[00]) } | math sum) == 2)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bytes-each-index-of-sum"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes each closure index-of math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    (($entry | each {|x| ($x | bytes index-of 0x[00]) } | math sum) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
