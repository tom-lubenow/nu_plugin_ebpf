export const VERIFIER_DIFF_FIXTURES_3745_3748 = [
    {
        name: "map-get-array-u64-all-zero"
        category: "maps"
        tags: [maps map-define map-get arrays u64 all closure accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define wide_ports --kind array --value-type "array{u64:2}" --max-entries 1'
            '  let entry = (0 | map-get wide_ports --kind array)'
            '  if $entry {'
            '    ($entry | all {|x| $x == 0 })'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u64-any-nonzero"
        category: "maps"
        tags: [maps map-define map-get arrays u64 any closure accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define wide_ports --kind array --value-type "array{u64:2}" --max-entries 1'
            '  let entry = (0 | map-get wide_ports --kind array)'
            '  if $entry {'
            '    ($entry | any {|x| $x != 0 })'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-hash-array-u64-all-zero"
        category: "maps"
        tags: [maps map-define map-get hash arrays u64 all closure accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define wide_hash_ports --kind hash --key-type u32 --value-type "array{u64:2}" --max-entries 1'
            '  let entry = (0 | map-get wide_hash_ports --kind hash)'
            '  if $entry {'
            '    ($entry | all {|x| $x == 0 })'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-hash-array-u64-any-nonzero"
        category: "maps"
        tags: [maps map-define map-get hash arrays u64 any closure accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define wide_hash_ports --kind hash --key-type u32 --value-type "array{u64:2}" --max-entries 1'
            '  let entry = (0 | map-get wide_hash_ports --kind hash)'
            '  if $entry {'
            '    ($entry | any {|x| $x != 0 })'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
