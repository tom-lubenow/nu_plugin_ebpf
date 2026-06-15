export const VERIFIER_DIFF_FIXTURES_3851_3851 = [
    {
        name: "map-put-nested-record-bool-array-field-last"
        category: "maps"
        tags: [maps map-define map-put map-get records arrays bool nested last accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{nested:record{flags:array{bool:2}},pid:u32}" --max-entries 1'
            '  { nested: { flags: [false true] } pid: 7 } | map-put states 0 --kind array'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get nested | get flags | last) == true) and (($entry | get pid) == 7)))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
