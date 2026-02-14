use super::*;

impl AnalysisCfg {
    pub fn build<F: CfgFunction>(func: &F) -> Self {
        let mut cfg = AnalysisCfg {
            entry: func.entry(),
            predecessors: HashMap::new(),
            successors: HashMap::new(),
            idom: HashMap::new(),
            rpo: Vec::new(),
            post_order: Vec::new(),
        };

        for block in func.blocks() {
            cfg.predecessors.insert(block.id(), Vec::new());
            cfg.successors.insert(block.id(), Vec::new());
        }

        for block in func.blocks() {
            let succs = block.successors();
            cfg.successors.insert(block.id(), succs.clone());
            for succ in succs {
                cfg.predecessors.entry(succ).or_default().push(block.id());
            }
        }

        cfg.compute_post_order(func);
        cfg.compute_dominators(func);
        cfg
    }

    fn compute_post_order<F: CfgFunction>(&mut self, func: &F) {
        let mut visited = HashSet::new();
        let mut post_order = Vec::new();

        fn dfs<F: CfgFunction>(
            block_id: BlockId,
            func: &F,
            cfg: &AnalysisCfg,
            visited: &mut HashSet<BlockId>,
            post_order: &mut Vec<BlockId>,
        ) {
            if visited.contains(&block_id) {
                return;
            }
            visited.insert(block_id);

            if let Some(succs) = cfg.successors.get(&block_id) {
                for &succ in succs {
                    if func.has_block(succ) {
                        dfs(succ, func, cfg, visited, post_order);
                    }
                }
            }

            post_order.push(block_id);
        }

        dfs(func.entry(), func, self, &mut visited, &mut post_order);
        self.post_order = post_order.clone();
        self.rpo = post_order.into_iter().rev().collect();
    }

    fn compute_dominators<F: CfgFunction>(&mut self, func: &F) {
        if func.blocks().is_empty() {
            return;
        }

        self.idom = compute_idom(func.entry(), func.blocks(), &self.predecessors, &self.rpo);
    }

    pub fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        dominates_in_idom(a, b, &self.idom)
    }
}

impl BlockLiveness {
    pub fn compute<F: CfgFunction>(func: &F, cfg: &AnalysisCfg) -> Self {
        let mut info = BlockLiveness {
            live_in: HashMap::new(),
            live_out: HashMap::new(),
        };

        for block in func.blocks() {
            info.live_in.insert(block.id(), HashSet::new());
            info.live_out.insert(block.id(), HashSet::new());
        }

        let mut changed = true;
        while changed {
            changed = false;

            for &block_id in &cfg.post_order {
                let block = func.block(block_id);

                let mut live_out = HashSet::new();
                for succ_id in block.successors() {
                    if let Some(succ_live_in) = info.live_in.get(&succ_id) {
                        live_out.extend(succ_live_in);
                    }
                }

                let mut live_in = live_out.clone();

                for def in block.terminator().defs() {
                    live_in.remove(&def);
                }
                for use_vreg in block.terminator().uses() {
                    live_in.insert(use_vreg);
                }

                for inst in block.instructions().iter().rev() {
                    for def in inst.defs() {
                        live_in.remove(&def);
                    }
                    for use_vreg in inst.uses() {
                        live_in.insert(use_vreg);
                    }
                }

                let old_live_in = info.live_in.get(&block_id).cloned().unwrap_or_default();
                let old_live_out = info.live_out.get(&block_id).cloned().unwrap_or_default();

                if live_in != old_live_in || live_out != old_live_out {
                    changed = true;
                    info.live_in.insert(block_id, live_in);
                    info.live_out.insert(block_id, live_out);
                }
            }
        }

        info
    }
}

impl GenericLoopInfo {
    pub fn compute<F: CfgFunction>(func: &F, cfg: &AnalysisCfg) -> Self {
        let mut info = GenericLoopInfo {
            loops: HashMap::new(),
            loop_depth: HashMap::new(),
        };

        for block in func.blocks() {
            info.loop_depth.insert(block.id(), 0);
        }

        let mut back_edges: Vec<(BlockId, BlockId)> = Vec::new();
        for block in func.blocks() {
            for &succ in cfg.successors.get(&block.id()).unwrap_or(&Vec::new()) {
                if cfg.dominates(succ, block.id()) {
                    back_edges.push((block.id(), succ));
                }
            }
        }

        for (tail, header) in back_edges {
            let mut loop_blocks = HashSet::new();
            loop_blocks.insert(header);

            let mut worklist = VecDeque::new();
            if tail != header {
                loop_blocks.insert(tail);
                worklist.push_back(tail);
            }

            while let Some(block) = worklist.pop_front() {
                for &pred in cfg.predecessors.get(&block).unwrap_or(&Vec::new()) {
                    if !loop_blocks.contains(&pred) {
                        loop_blocks.insert(pred);
                        worklist.push_back(pred);
                    }
                }
            }

            info.loops.entry(header).or_default().extend(loop_blocks);
        }

        for blocks in info.loops.values() {
            for &block in blocks {
                *info.loop_depth.entry(block).or_insert(0) += 1;
            }
        }

        info
    }
}

fn compute_idom<B>(
    entry: BlockId,
    blocks: &[B],
    predecessors: &HashMap<BlockId, Vec<BlockId>>,
    rpo: &[BlockId],
) -> HashMap<BlockId, BlockId>
where
    B: CfgBlock,
{
    let rpo_index: HashMap<BlockId, usize> = rpo.iter().enumerate().map(|(i, &b)| (b, i)).collect();

    let mut doms: HashMap<BlockId, Option<BlockId>> = HashMap::new();
    for block in blocks {
        doms.insert(block.id(), None);
    }
    doms.insert(entry, Some(entry));

    let mut changed = true;
    while changed {
        changed = false;

        for &block_id in rpo {
            if block_id == entry {
                continue;
            }

            let preds = predecessors.get(&block_id).cloned().unwrap_or_default();
            let mut new_idom = None;

            for &pred in &preds {
                if doms.get(&pred).and_then(|d| *d).is_some() {
                    new_idom = Some(pred);
                    break;
                }
            }

            if let Some(mut idom) = new_idom {
                for &pred in &preds {
                    if pred == idom {
                        continue;
                    }
                    if doms.get(&pred).and_then(|d| *d).is_some() {
                        idom = intersect(pred, idom, &doms, &rpo_index);
                    }
                }

                if doms.get(&block_id).and_then(|d| *d) != Some(idom) {
                    doms.insert(block_id, Some(idom));
                    changed = true;
                }
            }
        }
    }

    let mut idom = HashMap::new();
    for (block_id, dom) in doms {
        if let Some(parent) = dom
            && block_id != parent
        {
            idom.insert(block_id, parent);
        }
    }
    idom
}

fn intersect(
    b1: BlockId,
    b2: BlockId,
    doms: &HashMap<BlockId, Option<BlockId>>,
    rpo_index: &HashMap<BlockId, usize>,
) -> BlockId {
    let get_idx = |b: BlockId| rpo_index.get(&b).copied().unwrap_or(usize::MAX);

    let mut finger1 = b1;
    let mut finger2 = b2;

    while finger1 != finger2 {
        while get_idx(finger1) > get_idx(finger2) {
            match doms.get(&finger1).and_then(|d| *d) {
                Some(dom) if dom != finger1 => finger1 = dom,
                _ => return finger2,
            }
        }
        while get_idx(finger2) > get_idx(finger1) {
            match doms.get(&finger2).and_then(|d| *d) {
                Some(dom) if dom != finger2 => finger2 = dom,
                _ => return finger1,
            }
        }
    }
    finger1
}

pub(super) fn dominates_in_idom(a: BlockId, b: BlockId, idom: &HashMap<BlockId, BlockId>) -> bool {
    if a == b {
        return true;
    }
    let mut current = b;
    while let Some(&dom) = idom.get(&current) {
        if dom == a {
            return true;
        }
        if dom == current {
            break;
        }
        current = dom;
    }
    false
}
