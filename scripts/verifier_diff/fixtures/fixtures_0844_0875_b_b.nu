const VERIFIER_DIFF_FIXTURES_0844_0875_B_B = [
    {
        name: "flow-dissector-record-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = { keys: $ctx.flow_keys }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = { keys: ($ctx | get flow_keys) }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-upsert-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline upsert get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-insert-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline insert get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | insert keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-merge-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline merge get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | merge { keys: ($ctx | get flow_keys) })'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-default-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline default get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | default ($ctx | get flow_keys) keys)'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-update-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline update get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ keys: null } | update keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-select-reject-rename-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline select reject rename get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ keys: ($ctx | get flow_keys), keep: 1 } | select keys keep | reject keep | rename parsed)'
            '  $rec.parsed.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-spread-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record spread source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  let base = { keys: $ctx.flow_keys }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
