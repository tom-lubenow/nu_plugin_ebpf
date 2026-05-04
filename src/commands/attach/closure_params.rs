use std::collections::{HashMap, HashSet};

use nu_cmd_lang::create_default_context;
use nu_parser::parse;
use nu_protocol::ast::Expr;
use nu_protocol::engine::StateWorkingSet;
use nu_protocol::ir::{Instruction, IrBlock};
use nu_protocol::{BlockId, IN_VARIABLE_ID, Signature, Span, VarId};

use crate::compiler::hir::{HirClosureParam, HirClosureParamSource};

fn source_slice_for_span(source: &str, root_span: Span, span: Span) -> Option<&str> {
    if span.start < root_span.start || span.end > root_span.end {
        return None;
    }
    let start = span.start - root_span.start;
    let end = span.end - root_span.start;
    source.get(start..end)
}

fn signature_param_names(sig: &Signature) -> Vec<String> {
    let mut names = Vec::new();
    names.extend(
        sig.required_positional
            .iter()
            .map(|param| param.name.trim_start_matches('$').to_string()),
    );
    names.extend(
        sig.optional_positional
            .iter()
            .map(|param| param.name.trim_start_matches('$').to_string()),
    );
    if let Some(rest) = &sig.rest_positional {
        names.push(rest.name.trim_start_matches('$').to_string());
    }
    names
}

fn parse_closure_param_names(source: &str) -> Option<Vec<String>> {
    let engine_state = create_default_context();
    let mut working_set = StateWorkingSet::new(&engine_state);
    let top_block = parse(&mut working_set, None, source.as_bytes(), false);

    let closure_block_id = top_block
        .pipelines
        .iter()
        .flat_map(|pipeline| pipeline.elements.iter())
        .find_map(|element| match &element.expr.expr {
            Expr::Closure(block_id) | Expr::Block(block_id) => Some(*block_id),
            _ => None,
        })?;
    let closure_block = working_set.get_block(closure_block_id);
    Some(signature_param_names(&closure_block.signature))
}

fn variable_name_from_source_token(token: &str) -> Option<String> {
    let token = token.trim();
    let token = token.strip_prefix('$')?;
    let ident_len = token
        .char_indices()
        .take_while(|(_, ch)| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        .map(|(idx, ch)| idx + ch.len_utf8())
        .last()
        .unwrap_or(0);
    (ident_len > 0).then(|| token[..ident_len].to_string())
}

fn loaded_parameter_vars_by_name(
    source: &str,
    root_span: Span,
    ir_block: &IrBlock,
) -> HashMap<String, VarId> {
    let mut stored_vars = HashSet::new();
    for instruction in &ir_block.instructions {
        if let Instruction::StoreVariable { var_id, .. } = instruction {
            stored_vars.insert(*var_id);
        }
    }

    let mut vars = HashMap::new();
    for (idx, instruction) in ir_block.instructions.iter().enumerate() {
        let Instruction::LoadVariable { var_id, .. } = instruction else {
            continue;
        };
        if *var_id == IN_VARIABLE_ID || stored_vars.contains(var_id) {
            continue;
        }
        let Some(span) = ir_block.spans.get(idx).copied() else {
            continue;
        };
        let Some(token) = source_slice_for_span(source, root_span, span) else {
            continue;
        };
        let Some(name) = variable_name_from_source_token(token) else {
            continue;
        };
        vars.entry(name).or_insert(*var_id);
    }
    vars
}

pub(super) fn recover_closure_param_sources(
    source: &str,
    root_span: Span,
    closure_spans: &HashMap<BlockId, Span>,
    closure_irs: &HashMap<BlockId, IrBlock>,
) -> HashMap<BlockId, HirClosureParamSource> {
    let mut out = HashMap::new();

    for (block_id, ir_block) in closure_irs {
        let Some(block_span) = closure_spans.get(block_id).copied() else {
            continue;
        };
        let Some(block_source) = source_slice_for_span(source, root_span, block_span) else {
            continue;
        };
        let Some(names) = parse_closure_param_names(block_source) else {
            continue;
        };
        if names.is_empty() {
            continue;
        }

        let var_by_name = loaded_parameter_vars_by_name(source, root_span, ir_block);
        let params = names
            .into_iter()
            .map(|name| HirClosureParam {
                var_id: var_by_name.get(&name).copied(),
                name,
            })
            .collect();
        out.insert(*block_id, HirClosureParamSource { params });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use nu_protocol::{RegId, VarId};
    use std::sync::Arc;

    fn source_span(source: &str) -> Span {
        Span {
            start: 100,
            end: 100 + source.len(),
        }
    }

    fn source_var_span(source: &str, needle: &str) -> Span {
        let root = source_span(source);
        let start = source.find(needle).expect("needle should exist in source");
        Span {
            start: root.start + start,
            end: root.start + start + needle.len(),
        }
    }

    fn ir_block(instructions: Vec<Instruction>, spans: Vec<Span>) -> IrBlock {
        IrBlock {
            instructions,
            spans,
            data: Arc::from([]),
            ast: vec![],
            comments: vec![],
            register_count: 1,
            file_count: 0,
        }
    }

    #[test]
    fn test_recover_maps_used_trailing_param_by_declared_name() {
        let source = "{|timer key val| if $val { $val.cookie | count }; 0}";
        let block_id = BlockId::new(7);
        let root = source_span(source);
        let ir = ir_block(
            vec![Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(77),
            }],
            vec![source_var_span(source, "$val")],
        );
        let sources = recover_closure_param_sources(
            source,
            root,
            &HashMap::from([(block_id, root)]),
            &HashMap::from([(block_id, ir)]),
        );

        let params = &sources.get(&block_id).expect("source params").params;
        assert_eq!(params.len(), 3);
        assert_eq!(params[0].name, "timer");
        assert_eq!(params[0].var_id, None);
        assert_eq!(params[1].name, "key");
        assert_eq!(params[1].var_id, None);
        assert_eq!(params[2].name, "val");
        assert_eq!(params[2].var_id, Some(VarId::new(77)));
    }

    #[test]
    fn test_recover_preserves_unused_extra_declared_param() {
        let source = "{|timer key val extra| 0}";
        let block_id = BlockId::new(8);
        let root = source_span(source);
        let ir = ir_block(vec![], vec![]);
        let sources = recover_closure_param_sources(
            source,
            root,
            &HashMap::from([(block_id, root)]),
            &HashMap::from([(block_id, ir)]),
        );

        let params = &sources.get(&block_id).expect("source params").params;
        assert_eq!(params.len(), 4);
        assert_eq!(params[3].name, "extra");
        assert!(params.iter().all(|param| param.var_id.is_none()));
    }
}
