export const VERIFIER_DIFF_FIXTURES_3467_3469 = [
    {
        name: "map-define-array-u32-key-put-get"
        category: "maps"
        tags: [maps map-define global-define arrays u32 key map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_ports --kind hash --key-type "array{u32:2}" --value-type int'
            '  [7 9] | global-define --type "array{u32:2}" key_ports'
            '  let key = (global-get key_ports)'
            '  42 | map-put keyed_ports $key --kind hash'
            '  let entry = ($key | map-get keyed_ports --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-array-string-key-put-get"
        category: "maps"
        tags: [maps map-define global-define arrays string key map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_names --kind hash --key-type "array{string:8:2}" --value-type int'
            '  ["aa" "bb"] | global-define --type "array{string:8:2}" key_names'
            '  let key = (global-get key_names)'
            '  42 | map-put keyed_names $key --kind hash'
            '  let entry = ($key | map-get keyed_names --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-array-bytes-key-put-get"
        category: "maps"
        tags: [maps map-define global-define arrays binary bytes key map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_buffers --kind hash --key-type "array{bytes:4:2}" --value-type int'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" key_buffers'
            '  let key = (global-get key_buffers)'
            '  42 | map-put keyed_buffers $key --kind hash'
            '  let entry = ($key | map-get keyed_buffers --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
