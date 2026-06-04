//! Widened byte predicate commands used by compiled eBPF closures.

use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::{
    Category, Example, LabeledError, PipelineData, Signature, SyntaxShape, Type, Value,
};

use crate::EbpfPlugin;

#[derive(Clone)]
pub struct BytesStartsWith;

#[derive(Clone)]
pub struct BytesEndsWith;

fn binary_predicate_signature(name: &str) -> Signature {
    Signature::build(name)
        .input_output_types(vec![
            (Type::Binary, Type::Bool),
            (Type::list(Type::Binary), Type::list(Type::Bool)),
        ])
        .required(
            "pattern",
            SyntaxShape::Binary,
            "The binary pattern to match",
        )
        .category(Category::Bytes)
}

fn run_binary_predicate(
    call: &EvaluatedCall,
    input: PipelineData,
    matches: impl Fn(&[u8], &[u8]) -> bool,
) -> Result<PipelineData, LabeledError> {
    let pattern: Vec<u8> = call.req(0)?;
    let input = input.into_value(call.head)?;
    let span = input.span();

    let output = match input {
        Value::Binary { val, .. } => Value::bool(matches(&val, &pattern), span),
        Value::List { vals, .. } => {
            let mut out = Vec::with_capacity(vals.len());
            for (idx, item) in vals.into_iter().enumerate() {
                let item_span = item.span();
                let Value::Binary { val, .. } = item else {
                    return Err(LabeledError::new("Invalid byte predicate input")
                        .with_label(format!("expected binary at list index {}", idx), item_span));
                };
                out.push(Value::bool(matches(&val, &pattern), item_span));
            }
            Value::list(out, span)
        }
        other => {
            return Err(
                LabeledError::new("Invalid byte predicate input").with_label(
                    format!("expected binary or list<binary>, got {}", other.get_type()),
                    span,
                ),
            );
        }
    };

    Ok(PipelineData::Value(output, None))
}

impl PluginCommand for BytesStartsWith {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "bytes starts-with"
    }

    fn description(&self) -> &str {
        "Check whether binary input or each binary list item starts with a pattern."
    }

    fn signature(&self) -> Signature {
        binary_predicate_signature(self.name())
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "[0x[01 02] 0x[03 04]] | bytes starts-with 0x[03]",
            description: "Check each binary value in a list for a prefix",
            result: Some(Value::list(
                vec![
                    Value::bool(false, nu_protocol::Span::unknown()),
                    Value::bool(true, nu_protocol::Span::unknown()),
                ],
                nu_protocol::Span::unknown(),
            )),
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        run_binary_predicate(call, input, |input, pattern| input.starts_with(pattern))
    }
}

impl PluginCommand for BytesEndsWith {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "bytes ends-with"
    }

    fn description(&self) -> &str {
        "Check whether binary input or each binary list item ends with a pattern."
    }

    fn signature(&self) -> Signature {
        binary_predicate_signature(self.name())
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "[0x[01 02] 0x[03 04]] | bytes ends-with 0x[02]",
            description: "Check each binary value in a list for a suffix",
            result: Some(Value::list(
                vec![
                    Value::bool(true, nu_protocol::Span::unknown()),
                    Value::bool(false, nu_protocol::Span::unknown()),
                ],
                nu_protocol::Span::unknown(),
            )),
        }]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        run_binary_predicate(call, input, |input, pattern| input.ends_with(pattern))
    }
}
