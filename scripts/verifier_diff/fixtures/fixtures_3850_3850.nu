export const VERIFIER_DIFF_FIXTURES_3850_3850 = [
    {
        name: "map-put-record-bool-array-field-first"
        category: "maps"
        tags: [maps map-define map-put map-get records arrays bool first accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{flags:array{bool:2},pid:u32}" --max-entries 1'
            '  { flags: [true false] pid: 7 } | map-put states 0 --kind array'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    ((($entry | get flags | first) == true) and (($entry | get pid) == 7))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
