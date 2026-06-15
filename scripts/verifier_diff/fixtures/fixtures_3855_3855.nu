export const VERIFIER_DIFF_FIXTURES_3855_3855 = [
    {
        name: "map-push-stack-array-bool-direct-last"
        category: "maps"
        tags: [maps stack map-define map-push map-pop arrays bool last accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flag_stack --kind stack --value-type "array{bool:2}" --max-entries 1'
            '  [true false] | map-push flag_stack --kind stack'
            '  let entry = (map-pop flag_stack --kind stack)'
            '  if $entry {'
            '    (($entry | last) == false)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
