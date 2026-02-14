use super::*;

pub(super) fn env_free_vars(env: &SubfnSchemeMap) -> HashSet<TypeVar> {
    let mut vars = HashSet::new();
    for scheme in env.values() {
        vars.extend(scheme.free_vars());
    }
    vars
}

fn collect_subfn_calls(func: &MirFunction) -> Vec<SubfunctionId> {
    let mut calls = Vec::new();
    for block in &func.blocks {
        for inst in &block.instructions {
            if let MirInst::CallSubfn { subfn, .. } = inst {
                calls.push(*subfn);
            }
        }
        if let MirInst::CallSubfn { subfn, .. } = &block.terminator {
            calls.push(*subfn);
        }
    }
    calls
}

fn topo_sort_subfunctions(graph: &[Vec<usize>]) -> Result<Vec<usize>, TypeError> {
    fn dfs(
        node: usize,
        graph: &[Vec<usize>],
        state: &mut [u8],
        stack: &mut Vec<usize>,
        order: &mut Vec<usize>,
    ) -> Result<(), TypeError> {
        match state[node] {
            1 => {
                let mut cycle = stack.clone();
                cycle.push(node);
                let cycle_ids: Vec<String> = cycle
                    .into_iter()
                    .map(|idx| format!("subfn{}", idx))
                    .collect();
                return Err(TypeError::new(format!(
                    "recursive subfunction call detected: {} (polymorphic recursion requires explicit type annotations and is not currently supported)",
                    cycle_ids.join(" -> ")
                )));
            }
            2 => return Ok(()),
            _ => {}
        }

        state[node] = 1;
        stack.push(node);
        for &next in &graph[node] {
            dfs(next, graph, state, stack, order)?;
        }
        stack.pop();
        state[node] = 2;
        order.push(node);
        Ok(())
    }

    let mut state = vec![0u8; graph.len()];
    let mut order = Vec::new();
    let mut stack = Vec::new();

    for node in 0..graph.len() {
        if state[node] == 0 {
            dfs(node, graph, &mut state, &mut stack, &mut order)?;
        }
    }

    order.reverse();
    Ok(order)
}

pub fn infer_subfunction_schemes(
    subfunctions: &[MirFunction],
    probe_ctx: Option<ProbeContext>,
) -> Result<SubfnSchemeMap, Vec<TypeError>> {
    let mut errors = Vec::new();
    let mut graph = vec![Vec::new(); subfunctions.len()];

    for (idx, func) in subfunctions.iter().enumerate() {
        if func.param_count > 5 {
            errors.push(TypeError::new(format!(
                "BPF subfunctions support at most 5 arguments, got {} for subfn{}",
                func.param_count, idx
            )));
        }
        for subfn in collect_subfn_calls(func) {
            let target = subfn.0 as usize;
            if target >= subfunctions.len() {
                errors.push(TypeError::new(format!(
                    "Unknown subfunction ID {:?}",
                    subfn
                )));
            } else {
                graph[idx].push(target);
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let order = match topo_sort_subfunctions(&graph) {
        Ok(order) => order,
        Err(err) => return Err(vec![err]),
    };

    let mut schemes: SubfnSchemeMap = HashMap::new();

    for idx in order {
        let subfn_id = SubfunctionId(idx as u32);
        let func = &subfunctions[idx];
        let mut ti = TypeInference::new_with_env(probe_ctx.clone(), Some(&schemes), None, None);
        match ti.infer(func) {
            Ok(_) => {
                let scheme = ti.scheme_for_function(func, Some(&schemes));
                schemes.insert(subfn_id, scheme);
            }
            Err(errs) => return Err(errs),
        }
    }

    Ok(schemes)
}
