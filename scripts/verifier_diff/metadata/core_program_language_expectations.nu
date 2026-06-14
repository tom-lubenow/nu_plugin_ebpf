const PROGRAM_LANGUAGE_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  def make [] { 7 }'
            '  make'
            '}'
        ]
        feature_keys: ["compiled:bpf-subprogram-calls"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 4 {|i cb| 0 } "ctx" 0'
            '  0'
            '}'
        ]
        feature_keys: ["compiled:bpf-subprogram-calls"]
    }
    {
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key| 0} 0 0'
            '  0'
            '}'
        ]
        feature_keys: ["compiled:bpf-subprogram-calls"]
    }
    {
        program: [
            '{|ctx|'
            '  mut sum = 0'
            '  for i in 0..3 {'
            '    $sum = ($sum + $i)'
            '  }'
            '  $sum'
            '}'
        ]
        feature_keys: ["compiled:bounded-loops"]
    }
    {
        program: [
            '{|ctx|'
            '  # def ignored [] { for ignored in 0..1 { } }'
            '  let text = "def not_a_function [] { for item in [] { } }"'
            '  1'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  if true { for i in 0..3 { $i | count } }'
            '  0'
            '}'
        ]
        feature_keys: ["compiled:bounded-loops"]
    }
    {
        program: [
            '{|ctx|'
            '  def make [] { mut sum = 0; for i in 0..3 { $sum = ($sum + $i) }; $sum }'
            '  make'
            '}'
        ]
        feature_keys: ["compiled:bpf-subprogram-calls" "compiled:bounded-loops"]
    }
]
