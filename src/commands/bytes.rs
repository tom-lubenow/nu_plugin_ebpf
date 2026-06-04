//! Widened byte commands used by compiled eBPF closures.

use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::{
    Category, Example, LabeledError, PipelineData, Signature, SyntaxShape, Type, Value,
};

use crate::EbpfPlugin;

#[derive(Clone)]
pub struct BytesStartsWith;

#[derive(Clone)]
pub struct BytesEndsWith;

#[derive(Clone)]
pub struct BytesIndexOf;

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

fn binary_search_signature(name: &str) -> Signature {
    Signature::build(name)
        .input_output_types(vec![
            (Type::Binary, Type::Int),
            (Type::Binary, Type::list(Type::Int)),
            (Type::list(Type::Binary), Type::list(Type::Int)),
        ])
        .switch(
            "all",
            "Return all matching offsets for scalar binary input",
            None,
        )
        .switch("end", "Search from the end of the binary input", None)
        .required("pattern", SyntaxShape::Binary, "The binary pattern to find")
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

fn first_binary_index(input: &[u8], pattern: &[u8], search_from_end: bool) -> i64 {
    if pattern.len() > input.len() {
        return -1;
    }

    let mut windows = input.windows(pattern.len());
    let found = if search_from_end {
        windows.rposition(|candidate| candidate == pattern)
    } else {
        windows.position(|candidate| candidate == pattern)
    };
    found.map(|idx| idx as i64).unwrap_or(-1)
}

fn all_binary_indexes(input: &[u8], pattern: &[u8], search_from_end: bool) -> Vec<Value> {
    if pattern.len() > input.len() {
        return Vec::new();
    }

    let mut offsets = Vec::new();
    if search_from_end {
        let mut end = input.len();
        while end >= pattern.len() {
            let Some(found) = input[..end]
                .windows(pattern.len())
                .rposition(|candidate| candidate == pattern)
            else {
                break;
            };
            offsets.push(found as i64);
            end = found;
        }
    } else {
        let mut cursor = 0usize;
        while cursor + pattern.len() <= input.len() {
            if input[cursor..].starts_with(pattern) {
                offsets.push(cursor as i64);
                cursor += pattern.len();
            } else {
                cursor += 1;
            }
        }
    }
    offsets
        .into_iter()
        .map(|offset| Value::int(offset, nu_protocol::Span::unknown()))
        .collect()
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

impl PluginCommand for BytesIndexOf {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "bytes index-of"
    }

    fn description(&self) -> &str {
        "Find a binary pattern in binary input or each binary list item."
    }

    fn signature(&self) -> Signature {
        binary_search_signature(self.name())
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "[0x[01 02] 0x[03 02]] | bytes index-of 0x[02]",
            description: "Find the pattern offset in each binary value in a list",
            result: Some(Value::list(
                vec![
                    Value::int(1, nu_protocol::Span::unknown()),
                    Value::int(1, nu_protocol::Span::unknown()),
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
        let pattern: Vec<u8> = call.req(0)?;
        if pattern.is_empty() {
            return Err(LabeledError::new("Invalid byte search pattern").with_label(
                "bytes index-of requires a non-empty binary pattern",
                call.head,
            ));
        }
        let return_all = call.has_flag("all")?;
        let search_from_end = call.has_flag("end")?;
        let input = input.into_value(call.head)?;
        let span = input.span();

        let output = match input {
            Value::Binary { val, .. } if return_all => {
                Value::list(all_binary_indexes(&val, &pattern, search_from_end), span)
            }
            Value::Binary { val, .. } => {
                Value::int(first_binary_index(&val, &pattern, search_from_end), span)
            }
            Value::List { vals, .. } => {
                if return_all {
                    return Err(LabeledError::new("Invalid byte search input").with_label(
                        "bytes index-of --all does not support list<binary> input",
                        span,
                    ));
                }
                let mut out = Vec::with_capacity(vals.len());
                for (idx, item) in vals.into_iter().enumerate() {
                    let item_span = item.span();
                    let Value::Binary { val, .. } = item else {
                        return Err(LabeledError::new("Invalid byte search input").with_label(
                            format!("expected binary at list index {}", idx),
                            item_span,
                        ));
                    };
                    out.push(Value::int(
                        first_binary_index(&val, &pattern, search_from_end),
                        item_span,
                    ));
                }
                Value::list(out, span)
            }
            other => {
                return Err(LabeledError::new("Invalid byte search input").with_label(
                    format!("expected binary or list<binary>, got {}", other.get_type()),
                    span,
                ));
            }
        };

        Ok(PipelineData::Value(output, None))
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
