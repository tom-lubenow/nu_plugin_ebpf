export const VERIFIER_DIFF_FIXTURES_3376_3376 = [
    {
        name: "core-list-bits-binary-and-or-get"
        category: "language-core"
        tags: [aggregate list binary bits and or get bytes starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let and_ok = (([0x[f0 0f] 0x[aa cc]] | bits and 0x[0f f0] | get 1 | bytes starts-with 0x[0a c0]) == 1)'
            '  let or_ok = (([0x[10] 0x[20 03]] | bits or 0x[0f] | get 1 | bytes starts-with 0x[2f 0f]) == 1)'
            '  $and_ok and $or_ok'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
