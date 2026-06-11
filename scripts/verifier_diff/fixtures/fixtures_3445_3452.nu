export const VERIFIER_DIFF_FIXTURES_3445_3452 = [
    {
        name: "map-get-array-bytes-at-collect"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes at collect accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    ($entry | bytes at 1..2 | bytes collect | bytes starts-with 0x[00 00])'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bytes-at-get"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes at get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    ($entry | bytes at 1..2 | get 1 | bytes starts-with 0x[00 00])'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bytes-add-collect"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes add collect accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    ($entry | bytes add 0x[ff] --index 2 | bytes collect | bytes starts-with 0x[00 00 ff 00 00 00 00 ff])'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bytes-add-get"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes add get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    ($entry | bytes add 0x[ff] --index 2 | get 1 | bytes starts-with 0x[00 00 ff])'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bytes-replace-collect"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes replace collect accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    ($entry | bytes replace --all 0x[00] 0x[ff] | bytes collect | bytes starts-with 0x[ff ff ff ff ff])'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bytes-replace-get"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes replace get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    ($entry | bytes replace --all 0x[00] 0x[ff] | get 1 | bytes starts-with 0x[ff ff])'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bytes-remove-collect"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes remove collect accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    ($entry | bytes remove --all --end 0x[00 00 00 00 00] | bytes collect | bytes starts-with 0x[00 00 00 00 00])'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bytes-remove-get"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes remove get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    ($entry | bytes remove --all --end 0x[00 00 00 00 00] | get 1 | bytes starts-with 0x[00 00 00 00])'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
