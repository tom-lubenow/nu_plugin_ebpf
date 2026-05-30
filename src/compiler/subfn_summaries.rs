use std::collections::{HashMap, HashSet, VecDeque};

use super::instruction::{
    BpfHelper, KfuncRefKind, helper_acquire_ref_kind, helper_release_ref_kind,
    kfunc_acquire_ref_kind, kfunc_release_ref_arg_index, kfunc_release_ref_kind,
};
use super::mir::{BlockId, MirFunction, MirInst, MirValue, SubfunctionId, VReg};

const SUMMARY_ARG_SLOTS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubfunctionReturnSummary {
    Unknown,
    ReturnsArg(usize),
    UnknownChangesPacketData,
    ReturnsArgChangesPacketData(usize),
}

impl SubfunctionReturnSummary {
    pub(crate) const fn return_arg(self) -> Option<usize> {
        match self {
            Self::ReturnsArg(idx) | Self::ReturnsArgChangesPacketData(idx) => Some(idx),
            Self::Unknown | Self::UnknownChangesPacketData => None,
        }
    }

    pub(crate) const fn changes_packet_data(self) -> bool {
        matches!(
            self,
            Self::UnknownChangesPacketData | Self::ReturnsArgChangesPacketData(_)
        )
    }

    const fn from_parts(return_arg: Option<usize>, changes_packet_data: bool) -> Self {
        match (return_arg, changes_packet_data) {
            (Some(idx), false) => Self::ReturnsArg(idx),
            (Some(idx), true) => Self::ReturnsArgChangesPacketData(idx),
            (None, false) => Self::Unknown,
            (None, true) => Self::UnknownChangesPacketData,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SubfunctionSummary {
    return_summary: SubfunctionReturnSummary,
    kfunc_ref_return_kind: Option<KfuncRefKind>,
    ringbuf_record_release_args: u8,
    ringbuf_dynptr_release_args: u8,
    kfunc_ref_release_args: [Option<KfuncRefKind>; SUMMARY_ARG_SLOTS],
}

impl SubfunctionSummary {
    pub(crate) const fn unknown() -> Self {
        Self {
            return_summary: SubfunctionReturnSummary::Unknown,
            kfunc_ref_return_kind: None,
            ringbuf_record_release_args: 0,
            ringbuf_dynptr_release_args: 0,
            kfunc_ref_release_args: [None; SUMMARY_ARG_SLOTS],
        }
    }

    pub(crate) const fn from_return_summary(return_summary: SubfunctionReturnSummary) -> Self {
        Self {
            return_summary,
            kfunc_ref_return_kind: None,
            ringbuf_record_release_args: 0,
            ringbuf_dynptr_release_args: 0,
            kfunc_ref_release_args: [None; SUMMARY_ARG_SLOTS],
        }
    }

    pub(crate) const fn return_summary(self) -> SubfunctionReturnSummary {
        self.return_summary
    }

    pub(crate) const fn return_arg(self) -> Option<usize> {
        self.return_summary.return_arg()
    }

    pub(crate) const fn kfunc_ref_return_kind(self) -> Option<KfuncRefKind> {
        self.kfunc_ref_return_kind
    }

    pub(crate) const fn changes_packet_data(self) -> bool {
        self.return_summary.changes_packet_data()
    }

    pub(crate) const fn releases_ringbuf_record_arg(self, idx: usize) -> bool {
        idx < 8 && (self.ringbuf_record_release_args & (1 << idx)) != 0
    }

    pub(crate) const fn releases_ringbuf_dynptr_arg(self, idx: usize) -> bool {
        idx < 8 && (self.ringbuf_dynptr_release_args & (1 << idx)) != 0
    }

    pub(crate) const fn kfunc_ref_release_arg_kind(self, idx: usize) -> Option<KfuncRefKind> {
        if idx < SUMMARY_ARG_SLOTS {
            self.kfunc_ref_release_args[idx]
        } else {
            None
        }
    }

    const fn from_parts(
        return_arg: Option<usize>,
        kfunc_ref_return_kind: Option<KfuncRefKind>,
        changes_packet_data: bool,
        ringbuf_record_release_args: u8,
        ringbuf_dynptr_release_args: u8,
        kfunc_ref_release_args: [Option<KfuncRefKind>; SUMMARY_ARG_SLOTS],
    ) -> Self {
        Self {
            return_summary: SubfunctionReturnSummary::from_parts(return_arg, changes_packet_data),
            kfunc_ref_return_kind,
            ringbuf_record_release_args,
            ringbuf_dynptr_release_args,
            kfunc_ref_release_args,
        }
    }
}

impl From<SubfunctionReturnSummary> for SubfunctionSummary {
    fn from(return_summary: SubfunctionReturnSummary) -> Self {
        Self::from_return_summary(return_summary)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AliasSource {
    Unknown,
    Param(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KfuncRefSource {
    id: VReg,
    kind: KfuncRefKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SummaryState {
    aliases: Vec<AliasSource>,
    kfunc_ref_sources: Vec<Option<KfuncRefSource>>,
    ringbuf_record_release_args: u8,
    ringbuf_dynptr_release_args: u8,
    kfunc_ref_release_args: [Option<KfuncRefKind>; SUMMARY_ARG_SLOTS],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct InstEffects {
    changes_packet_data: bool,
}

pub(crate) fn infer_subfunction_return_summaries(
    subfunctions: &[MirFunction],
) -> HashMap<SubfunctionId, SubfunctionReturnSummary> {
    infer_subfunction_summaries(subfunctions)
        .into_iter()
        .map(|(subfn, summary)| (subfn, summary.return_summary()))
        .collect()
}

pub(crate) fn infer_subfunction_summaries(
    subfunctions: &[MirFunction],
) -> HashMap<SubfunctionId, SubfunctionSummary> {
    let mut summaries = HashMap::new();
    let mut visiting = HashSet::new();

    for idx in 0..subfunctions.len() {
        let subfn = SubfunctionId(idx as u32);
        infer_summary_for_subfunction(subfn, subfunctions, &mut summaries, &mut visiting);
    }

    summaries
}

fn infer_summary_for_subfunction(
    subfn: SubfunctionId,
    subfunctions: &[MirFunction],
    summaries: &mut HashMap<SubfunctionId, SubfunctionSummary>,
    visiting: &mut HashSet<SubfunctionId>,
) -> SubfunctionSummary {
    if let Some(summary) = summaries.get(&subfn) {
        return *summary;
    }

    if !visiting.insert(subfn) {
        return SubfunctionSummary::unknown();
    }

    let summary = subfunctions
        .get(subfn.0 as usize)
        .map(|func| summarize_function(func, subfunctions, summaries, visiting))
        .unwrap_or_else(SubfunctionSummary::unknown);
    visiting.remove(&subfn);
    summaries.insert(subfn, summary);
    summary
}

fn summarize_function(
    func: &MirFunction,
    subfunctions: &[MirFunction],
    summaries: &mut HashMap<SubfunctionId, SubfunctionSummary>,
    visiting: &mut HashSet<SubfunctionId>,
) -> SubfunctionSummary {
    let total_vregs = func.vreg_count.max(func.param_count as u32) as usize;
    let mut in_states: HashMap<BlockId, SummaryState> = HashMap::new();
    let mut worklist: VecDeque<BlockId> = VecDeque::new();

    let mut entry_state = vec![AliasSource::Unknown; total_vregs];
    for idx in 0..func.param_count.min(total_vregs) {
        entry_state[idx] = AliasSource::Param(idx);
    }
    let param_stack_aliases: HashMap<_, _> = func
        .param_stack_slots
        .iter()
        .map(|(param_idx, slot)| (*slot, *param_idx))
        .collect();
    in_states.insert(
        func.entry,
        SummaryState {
            aliases: entry_state,
            kfunc_ref_sources: vec![None; total_vregs],
            ringbuf_record_release_args: 0,
            ringbuf_dynptr_release_args: 0,
            kfunc_ref_release_args: [None; SUMMARY_ARG_SLOTS],
        },
    );
    worklist.push_back(func.entry);

    let mut return_alias: Option<Option<usize>> = None;
    let mut returned_kfunc_ref: Option<Option<KfuncRefKind>> = None;
    let mut changes_packet_data = false;
    let mut returned_record_releases: Option<u8> = None;
    let mut returned_dynptr_releases: Option<u8> = None;
    let mut returned_kfunc_releases: Option<[Option<KfuncRefKind>; SUMMARY_ARG_SLOTS]> = None;

    while let Some(block_id) = worklist.pop_front() {
        let Some(state_in) = in_states.get(&block_id).cloned() else {
            continue;
        };
        let block = func.block(block_id);
        let mut state = state_in;

        for inst in &block.instructions {
            let effects = apply_alias_inst(
                inst,
                &func.global_param_aliases,
                &param_stack_aliases,
                &mut state,
                subfunctions,
                summaries,
                visiting,
            );
            changes_packet_data |= effects.changes_packet_data;
        }

        match &block.terminator {
            MirInst::Jump { target } => {
                propagate_alias_state(*target, &state, &mut in_states, &mut worklist);
            }
            MirInst::Branch {
                if_true, if_false, ..
            } => {
                propagate_alias_state(*if_true, &state, &mut in_states, &mut worklist);
                propagate_alias_state(*if_false, &state, &mut in_states, &mut worklist);
            }
            MirInst::LoopHeader {
                counter,
                body,
                exit,
                ..
            } => {
                let mut body_state = state.clone();
                set_alias(&mut body_state.aliases, *counter, AliasSource::Unknown);
                propagate_alias_state(*body, &body_state, &mut in_states, &mut worklist);
                propagate_alias_state(*exit, &state, &mut in_states, &mut worklist);
            }
            MirInst::LoopBack { header, .. } => {
                propagate_alias_state(*header, &state, &mut in_states, &mut worklist);
            }
            MirInst::Return { val } => {
                let alias = alias_for_value(val.as_ref(), &state.aliases, &param_stack_aliases);
                return_alias = match return_alias {
                    None => Some(alias),
                    Some(existing) if existing == alias => Some(existing),
                    Some(_) => Some(None),
                };
                let returned_ref = kfunc_ref_return_kind_for_value(val.as_ref(), &state);
                returned_kfunc_ref = match returned_kfunc_ref {
                    None => Some(returned_ref),
                    Some(existing) if existing == returned_ref => Some(existing),
                    Some(_) => Some(None),
                };
                returned_record_releases = Some(match returned_record_releases {
                    None => state.ringbuf_record_release_args,
                    Some(existing) => existing & state.ringbuf_record_release_args,
                });
                returned_dynptr_releases = Some(match returned_dynptr_releases {
                    None => state.ringbuf_dynptr_release_args,
                    Some(existing) => existing & state.ringbuf_dynptr_release_args,
                });
                returned_kfunc_releases = Some(match returned_kfunc_releases {
                    None => state.kfunc_ref_release_args,
                    Some(existing) => {
                        merge_kfunc_release_args(existing, state.kfunc_ref_release_args)
                    }
                });
            }
            MirInst::TailCall { .. } | MirInst::Placeholder => {}
            _ => {}
        }

        if matches!(block.terminator, MirInst::TailCall { .. }) {
            changes_packet_data = true;
        }
    }

    SubfunctionSummary::from_parts(
        return_alias.flatten(),
        returned_kfunc_ref.flatten(),
        changes_packet_data,
        returned_record_releases.unwrap_or(0),
        returned_dynptr_releases.unwrap_or(0),
        returned_kfunc_releases.unwrap_or([None; SUMMARY_ARG_SLOTS]),
    )
}

fn propagate_alias_state(
    target: BlockId,
    next_state: &SummaryState,
    in_states: &mut HashMap<BlockId, SummaryState>,
    worklist: &mut VecDeque<BlockId>,
) {
    let changed = match in_states.get_mut(&target) {
        Some(existing) => merge_alias_states(existing, next_state),
        None => {
            in_states.insert(target, next_state.clone());
            true
        }
    };

    if changed {
        worklist.push_back(target);
    }
}

fn merge_alias_states(existing: &mut SummaryState, incoming: &SummaryState) -> bool {
    let mut changed = false;
    for (dst, src) in existing
        .aliases
        .iter_mut()
        .zip(incoming.aliases.iter().copied())
    {
        let merged = match (*dst, src) {
            (AliasSource::Param(lhs), AliasSource::Param(rhs)) if lhs == rhs => *dst,
            _ => AliasSource::Unknown,
        };
        if *dst != merged {
            *dst = merged;
            changed = true;
        }
    }
    for (dst, src) in existing
        .kfunc_ref_sources
        .iter_mut()
        .zip(incoming.kfunc_ref_sources.iter().copied())
    {
        let merged = if *dst == src { *dst } else { None };
        if *dst != merged {
            *dst = merged;
            changed = true;
        }
    }
    let record_releases =
        existing.ringbuf_record_release_args & incoming.ringbuf_record_release_args;
    if existing.ringbuf_record_release_args != record_releases {
        existing.ringbuf_record_release_args = record_releases;
        changed = true;
    }
    let dynptr_releases =
        existing.ringbuf_dynptr_release_args & incoming.ringbuf_dynptr_release_args;
    if existing.ringbuf_dynptr_release_args != dynptr_releases {
        existing.ringbuf_dynptr_release_args = dynptr_releases;
        changed = true;
    }
    let kfunc_releases = merge_kfunc_release_args(
        existing.kfunc_ref_release_args,
        incoming.kfunc_ref_release_args,
    );
    if existing.kfunc_ref_release_args != kfunc_releases {
        existing.kfunc_ref_release_args = kfunc_releases;
        changed = true;
    }
    changed
}

fn merge_kfunc_release_args(
    existing: [Option<KfuncRefKind>; SUMMARY_ARG_SLOTS],
    incoming: [Option<KfuncRefKind>; SUMMARY_ARG_SLOTS],
) -> [Option<KfuncRefKind>; SUMMARY_ARG_SLOTS] {
    let mut merged = [None; SUMMARY_ARG_SLOTS];
    for idx in 0..SUMMARY_ARG_SLOTS {
        merged[idx] = if existing[idx] == incoming[idx] {
            existing[idx]
        } else {
            None
        };
    }
    merged
}

fn apply_alias_inst(
    inst: &MirInst,
    global_param_aliases: &HashMap<String, usize>,
    param_stack_aliases: &HashMap<super::mir::StackSlotId, usize>,
    state: &mut SummaryState,
    subfunctions: &[MirFunction],
    summaries: &mut HashMap<SubfunctionId, SubfunctionSummary>,
    visiting: &mut HashSet<SubfunctionId>,
) -> InstEffects {
    match inst {
        MirInst::Copy { dst, src } => {
            let alias = alias_for_mir_value(src, &state.aliases, param_stack_aliases);
            set_alias(&mut state.aliases, *dst, alias);
            let kfunc_ref_source = kfunc_ref_source_for_mir_value(src, state);
            set_kfunc_ref_source(&mut state.kfunc_ref_sources, *dst, kfunc_ref_source);
            InstEffects::default()
        }
        MirInst::Phi { dst, args } => {
            let mut alias = AliasSource::Unknown;
            let mut kfunc_ref_source = None;
            let mut first = true;
            for (_, arg) in args {
                let current = get_alias(&state.aliases, *arg);
                let current_ref_source = kfunc_ref_source_for_vreg(state, *arg);
                if first {
                    alias = current;
                    kfunc_ref_source = current_ref_source;
                    first = false;
                } else if alias != current {
                    alias = AliasSource::Unknown;
                }
                if !first && kfunc_ref_source != current_ref_source {
                    kfunc_ref_source = None;
                }
            }
            set_alias(&mut state.aliases, *dst, alias);
            set_kfunc_ref_source(&mut state.kfunc_ref_sources, *dst, kfunc_ref_source);
            InstEffects::default()
        }
        MirInst::CallSubfn { dst, subfn, args } => {
            let summary = infer_summary_for_subfunction(*subfn, subfunctions, summaries, visiting);
            let alias = match summary.return_arg() {
                Some(idx) => args
                    .get(idx)
                    .copied()
                    .map(|arg| get_alias(&state.aliases, arg))
                    .unwrap_or(AliasSource::Unknown),
                None => AliasSource::Unknown,
            };
            set_alias(&mut state.aliases, *dst, alias);
            let kfunc_ref_source = match summary.return_arg() {
                Some(idx) => args
                    .get(idx)
                    .copied()
                    .and_then(|arg| kfunc_ref_source_for_vreg(state, arg)),
                None => summary
                    .kfunc_ref_return_kind()
                    .map(|kind| KfuncRefSource { id: *dst, kind }),
            };
            set_kfunc_ref_source(&mut state.kfunc_ref_sources, *dst, kfunc_ref_source);
            apply_subfunction_release_summary(summary, args, state);
            InstEffects {
                changes_packet_data: summary.changes_packet_data(),
            }
        }
        MirInst::LoadGlobal { dst, symbol, .. } => {
            let alias = global_param_aliases
                .get(symbol)
                .copied()
                .map(AliasSource::Param)
                .unwrap_or(AliasSource::Unknown);
            set_alias(&mut state.aliases, *dst, alias);
            set_kfunc_ref_source(&mut state.kfunc_ref_sources, *dst, None);
            InstEffects::default()
        }
        MirInst::CallHelper { dst, helper, .. } => {
            set_alias(&mut state.aliases, *dst, AliasSource::Unknown);
            apply_helper_release_summary(inst, state, param_stack_aliases);
            let kfunc_ref_source = BpfHelper::from_u32(*helper)
                .and_then(helper_acquire_ref_kind)
                .map(|kind| KfuncRefSource { id: *dst, kind });
            set_kfunc_ref_source(&mut state.kfunc_ref_sources, *dst, kfunc_ref_source);
            InstEffects {
                changes_packet_data: BpfHelper::from_u32(*helper)
                    .map(BpfHelper::changes_packet_data_in_subprogram)
                    .unwrap_or(false),
            }
        }
        MirInst::CallKfunc {
            dst, kfunc, args, ..
        } => {
            set_alias(&mut state.aliases, *dst, AliasSource::Unknown);
            apply_kfunc_release_summary(kfunc, args, state);
            let kfunc_ref_source =
                kfunc_acquire_ref_kind(kfunc).map(|kind| KfuncRefSource { id: *dst, kind });
            set_kfunc_ref_source(&mut state.kfunc_ref_sources, *dst, kfunc_ref_source);
            InstEffects::default()
        }
        MirInst::BinOp { dst, .. }
        | MirInst::UnaryOp { dst, .. }
        | MirInst::LoadMapFd { dst, .. }
        | MirInst::LoadSubprogram { dst, .. }
        | MirInst::MapLookup { dst, .. }
        | MirInst::MapLookupDynamic { dst, .. }
        | MirInst::LoadCtxField { dst, .. }
        | MirInst::ListNew { dst, .. }
        | MirInst::ListLen { dst, .. }
        | MirInst::ListGet { dst, .. }
        | MirInst::StopTimer { dst }
        | MirInst::Load { dst, .. }
        | MirInst::LoadSlot { dst, .. }
        | MirInst::StrCmp { dst, .. }
        | MirInst::LoopHeader { counter: dst, .. } => {
            set_alias(&mut state.aliases, *dst, AliasSource::Unknown);
            set_kfunc_ref_source(&mut state.kfunc_ref_sources, *dst, None);
            InstEffects::default()
        }
        MirInst::Store { .. }
        | MirInst::StoreSlot { .. }
        | MirInst::StoreCtxField { .. }
        | MirInst::ReadStr { .. }
        | MirInst::EmitEvent { .. }
        | MirInst::EmitRecord { .. }
        | MirInst::MapUpdate { .. }
        | MirInst::MapUpdateDynamic { .. }
        | MirInst::MapDelete { .. }
        | MirInst::MapDeleteDynamic { .. }
        | MirInst::MapPush { .. }
        | MirInst::Histogram { .. }
        | MirInst::StartTimer
        | MirInst::TailCall { .. }
        | MirInst::Jump { .. }
        | MirInst::Branch { .. }
        | MirInst::Return { .. }
        | MirInst::LoopBack { .. }
        | MirInst::Placeholder
        | MirInst::ListPush { .. }
        | MirInst::StringAppend { .. }
        | MirInst::IntToString { .. }
        | MirInst::RecordStore { .. } => InstEffects::default(),
    }
}

fn apply_subfunction_release_summary(
    summary: SubfunctionSummary,
    args: &[VReg],
    state: &mut SummaryState,
) {
    for idx in 0..5 {
        let Some(arg) = args.get(idx) else {
            continue;
        };
        if summary.releases_ringbuf_record_arg(idx)
            || summary.releases_ringbuf_dynptr_arg(idx)
            || summary.kfunc_ref_release_arg_kind(idx).is_some()
        {
            clear_kfunc_ref_source_for_vreg(state, *arg);
        }
        let AliasSource::Param(param_idx) = get_alias(&state.aliases, *arg) else {
            continue;
        };
        if summary.releases_ringbuf_record_arg(idx) {
            set_mask_bit(&mut state.ringbuf_record_release_args, param_idx);
        }
        if summary.releases_ringbuf_dynptr_arg(idx) {
            set_mask_bit(&mut state.ringbuf_dynptr_release_args, param_idx);
        }
        if let Some(kind) = summary.kfunc_ref_release_arg_kind(idx) {
            set_kfunc_release_arg(&mut state.kfunc_ref_release_args, param_idx, kind);
        }
    }
}

fn apply_helper_release_summary(
    inst: &MirInst,
    state: &mut SummaryState,
    param_stack_aliases: &HashMap<super::mir::StackSlotId, usize>,
) {
    let MirInst::CallHelper { helper, args, .. } = inst else {
        return;
    };
    let Some(helper) = BpfHelper::from_u32(*helper) else {
        return;
    };
    let Some(arg0) = args.first() else {
        return;
    };
    if let MirValue::VReg(arg) = arg0 {
        clear_kfunc_ref_source_for_vreg(state, *arg);
    }
    let alias = alias_for_mir_value(arg0, &state.aliases, param_stack_aliases);
    let AliasSource::Param(param_idx) = alias else {
        return;
    };
    match helper {
        BpfHelper::RingbufSubmit | BpfHelper::RingbufDiscard => {
            set_mask_bit(&mut state.ringbuf_record_release_args, param_idx);
        }
        BpfHelper::RingbufSubmitDynptr | BpfHelper::RingbufDiscardDynptr => {
            set_mask_bit(&mut state.ringbuf_dynptr_release_args, param_idx);
        }
        _ => {}
    }
    if let Some(kind) = helper_release_ref_kind(helper) {
        set_kfunc_release_arg(&mut state.kfunc_ref_release_args, param_idx, kind);
    }
}

fn apply_kfunc_release_summary(kfunc: &str, args: &[VReg], state: &mut SummaryState) {
    let Some(kind) = kfunc_release_ref_kind(kfunc) else {
        return;
    };
    let Some(arg_idx) = kfunc_release_ref_arg_index(kfunc) else {
        return;
    };
    let Some(arg) = args.get(arg_idx) else {
        return;
    };
    clear_kfunc_ref_source_for_vreg(state, *arg);
    let AliasSource::Param(param_idx) = get_alias(&state.aliases, *arg) else {
        return;
    };
    set_kfunc_release_arg(&mut state.kfunc_ref_release_args, param_idx, kind);
}

fn set_mask_bit(mask: &mut u8, idx: usize) {
    if idx < 8 {
        *mask |= 1 << idx;
    }
}

fn set_kfunc_release_arg(
    args: &mut [Option<KfuncRefKind>; SUMMARY_ARG_SLOTS],
    idx: usize,
    kind: KfuncRefKind,
) {
    if idx < SUMMARY_ARG_SLOTS {
        args[idx] = Some(kind);
    }
}

fn alias_for_value(
    val: Option<&MirValue>,
    state: &[AliasSource],
    param_stack_aliases: &HashMap<super::mir::StackSlotId, usize>,
) -> Option<usize> {
    match val {
        Some(value) => match alias_for_mir_value(value, state, param_stack_aliases) {
            AliasSource::Param(idx) => Some(idx),
            AliasSource::Unknown => None,
        },
        None => None,
    }
}

fn kfunc_ref_return_kind_for_value(
    val: Option<&MirValue>,
    state: &SummaryState,
) -> Option<KfuncRefKind> {
    let Some(MirValue::VReg(vreg)) = val else {
        return None;
    };
    kfunc_ref_source_for_vreg(state, *vreg).map(|source| source.kind)
}

fn kfunc_ref_source_for_mir_value(
    value: &MirValue,
    state: &SummaryState,
) -> Option<KfuncRefSource> {
    match value {
        MirValue::VReg(vreg) => kfunc_ref_source_for_vreg(state, *vreg),
        MirValue::StackSlot(_) | MirValue::Const(_) => None,
    }
}

fn kfunc_ref_source_for_vreg(state: &SummaryState, vreg: VReg) -> Option<KfuncRefSource> {
    state
        .kfunc_ref_sources
        .get(vreg.0 as usize)
        .copied()
        .flatten()
}

fn set_kfunc_ref_source(
    sources: &mut [Option<KfuncRefSource>],
    vreg: VReg,
    source: Option<KfuncRefSource>,
) {
    if let Some(slot) = sources.get_mut(vreg.0 as usize) {
        *slot = source;
    }
}

fn clear_kfunc_ref_source_for_vreg(state: &mut SummaryState, vreg: VReg) {
    let Some(source) = kfunc_ref_source_for_vreg(state, vreg) else {
        return;
    };
    for slot in &mut state.kfunc_ref_sources {
        if *slot == Some(source) {
            *slot = None;
        }
    }
}

fn alias_for_mir_value(
    value: &MirValue,
    state: &[AliasSource],
    param_stack_aliases: &HashMap<super::mir::StackSlotId, usize>,
) -> AliasSource {
    match value {
        MirValue::VReg(vreg) => get_alias(state, *vreg),
        MirValue::StackSlot(slot) => param_stack_aliases
            .get(slot)
            .copied()
            .map(AliasSource::Param)
            .unwrap_or(AliasSource::Unknown),
        MirValue::Const(_) => AliasSource::Unknown,
    }
}

fn get_alias(state: &[AliasSource], vreg: VReg) -> AliasSource {
    state
        .get(vreg.0 as usize)
        .copied()
        .unwrap_or(AliasSource::Unknown)
}

fn set_alias(state: &mut [AliasSource], vreg: VReg, alias: AliasSource) {
    if let Some(slot) = state.get_mut(vreg.0 as usize) {
        *slot = alias;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::mir::{MirFunction, MirInst, MirValue};

    #[test]
    fn test_infer_return_summary_for_copied_param() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;

        let copied = subfn.alloc_vreg();
        subfn.block_mut(entry).instructions.push(MirInst::Copy {
            dst: copied,
            src: MirValue::VReg(VReg(0)),
        });
        subfn.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(copied)),
        };

        let summaries = infer_subfunction_return_summaries(&[subfn]);
        assert_eq!(
            summaries.get(&SubfunctionId(0)),
            Some(&SubfunctionReturnSummary::ReturnsArg(0))
        );
    }

    #[test]
    fn test_infer_return_summary_through_nested_subfunction_call() {
        let mut callee = MirFunction::new();
        let callee_entry = callee.alloc_block();
        callee.entry = callee_entry;
        callee.param_count = 1;
        callee.block_mut(callee_entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(VReg(0))),
        };

        let mut caller = MirFunction::new();
        let caller_entry = caller.alloc_block();
        caller.entry = caller_entry;
        caller.param_count = 1;
        let ret = caller.alloc_vreg();
        caller
            .block_mut(caller_entry)
            .instructions
            .push(MirInst::CallSubfn {
                dst: ret,
                subfn: SubfunctionId(0),
                args: vec![VReg(0)],
            });
        caller.block_mut(caller_entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(ret)),
        };

        let summaries = infer_subfunction_return_summaries(&[callee, caller]);
        assert_eq!(
            summaries.get(&SubfunctionId(1)),
            Some(&SubfunctionReturnSummary::ReturnsArg(0))
        );
    }

    #[test]
    fn test_infer_return_summary_for_aliased_global_param() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;
        subfn
            .global_param_aliases
            .insert("__nu_local_global_250".to_string(), 0);

        let loaded = subfn.alloc_vreg();
        subfn
            .block_mut(entry)
            .instructions
            .push(MirInst::LoadGlobal {
                dst: loaded,
                symbol: "__nu_local_global_250".to_string(),
                ty: crate::compiler::mir::MirType::Ptr {
                    pointee: Box::new(crate::compiler::mir::MirType::Unknown),
                    address_space: crate::compiler::mir::AddressSpace::Map,
                },
            });
        subfn.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(loaded)),
        };

        let summaries = infer_subfunction_return_summaries(&[subfn]);
        assert_eq!(
            summaries.get(&SubfunctionId(0)),
            Some(&SubfunctionReturnSummary::ReturnsArg(0))
        );
    }

    #[test]
    fn test_infer_summary_tracks_packet_mutating_helper() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;

        let ret = subfn.alloc_vreg();
        subfn
            .block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: ret,
                helper: BpfHelper::MsgPushData as u32,
                args: vec![
                    MirValue::VReg(VReg(0)),
                    MirValue::Const(0),
                    MirValue::Const(8),
                    MirValue::Const(0),
                ],
            });
        subfn.block_mut(entry).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_return_summaries(&[subfn]);
        assert_eq!(
            summaries.get(&SubfunctionId(0)),
            Some(&SubfunctionReturnSummary::UnknownChangesPacketData)
        );
    }

    #[test]
    fn test_infer_summary_propagates_nested_packet_mutation() {
        let mut callee = MirFunction::new();
        let callee_entry = callee.alloc_block();
        callee.entry = callee_entry;
        callee.param_count = 1;
        let callee_ret = callee.alloc_vreg();
        callee
            .block_mut(callee_entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: callee_ret,
                helper: BpfHelper::SkbPullData as u32,
                args: vec![MirValue::VReg(VReg(0)), MirValue::Const(0)],
            });
        callee.block_mut(callee_entry).terminator = MirInst::Return { val: None };

        let mut caller = MirFunction::new();
        let caller_entry = caller.alloc_block();
        caller.entry = caller_entry;
        caller.param_count = 1;
        caller.vreg_count = 1;
        let call_ret = caller.alloc_vreg();
        caller
            .block_mut(caller_entry)
            .instructions
            .push(MirInst::CallSubfn {
                dst: call_ret,
                subfn: SubfunctionId(0),
                args: vec![VReg(0)],
            });
        caller.block_mut(caller_entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(VReg(0))),
        };

        let summaries = infer_subfunction_return_summaries(&[callee, caller]);
        assert_eq!(
            summaries.get(&SubfunctionId(1)),
            Some(&SubfunctionReturnSummary::ReturnsArgChangesPacketData(0))
        );
    }

    #[test]
    fn test_infer_summary_tracks_ringbuf_record_release_arg() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;
        subfn.vreg_count = 1;
        let submit_ret = subfn.alloc_vreg();
        subfn
            .block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: submit_ret,
                helper: BpfHelper::RingbufSubmit as u32,
                args: vec![MirValue::VReg(VReg(0)), MirValue::Const(0)],
            });
        subfn.block_mut(entry).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .copied()
            .expect("expected summary");
        assert!(summary.releases_ringbuf_record_arg(0));
        assert!(!summary.releases_ringbuf_record_arg(1));
    }

    #[test]
    fn test_infer_summary_requires_ringbuf_record_release_on_all_returns() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        let release = subfn.alloc_block();
        let done = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;
        subfn.vreg_count = 2;
        subfn.block_mut(entry).terminator = MirInst::Branch {
            cond: VReg(1),
            if_true: release,
            if_false: done,
        };
        let submit_ret = subfn.alloc_vreg();
        subfn
            .block_mut(release)
            .instructions
            .push(MirInst::CallHelper {
                dst: submit_ret,
                helper: BpfHelper::RingbufSubmit as u32,
                args: vec![MirValue::VReg(VReg(0)), MirValue::Const(0)],
            });
        subfn.block_mut(release).terminator = MirInst::Return { val: None };
        subfn.block_mut(done).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .copied()
            .expect("expected summary");
        assert!(!summary.releases_ringbuf_record_arg(0));
    }

    #[test]
    fn test_infer_summary_propagates_nested_ringbuf_dynptr_release_arg() {
        let mut callee = MirFunction::new();
        let callee_entry = callee.alloc_block();
        callee.entry = callee_entry;
        callee.param_count = 1;
        callee.vreg_count = 1;
        let submit_ret = callee.alloc_vreg();
        callee
            .block_mut(callee_entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: submit_ret,
                helper: BpfHelper::RingbufSubmitDynptr as u32,
                args: vec![MirValue::VReg(VReg(0)), MirValue::Const(0)],
            });
        callee.block_mut(callee_entry).terminator = MirInst::Return { val: None };

        let mut caller = MirFunction::new();
        let caller_entry = caller.alloc_block();
        caller.entry = caller_entry;
        caller.param_count = 1;
        caller.vreg_count = 1;
        let call_ret = caller.alloc_vreg();
        caller
            .block_mut(caller_entry)
            .instructions
            .push(MirInst::CallSubfn {
                dst: call_ret,
                subfn: SubfunctionId(0),
                args: vec![VReg(0)],
            });
        caller.block_mut(caller_entry).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[callee, caller]);
        let summary = summaries
            .get(&SubfunctionId(1))
            .copied()
            .expect("expected summary");
        assert!(summary.releases_ringbuf_dynptr_arg(0));
        assert!(!summary.releases_ringbuf_dynptr_arg(1));
    }

    #[test]
    fn test_infer_summary_tracks_kfunc_ref_release_arg() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;
        subfn.vreg_count = 1;
        let release_ret = subfn.alloc_vreg();
        subfn
            .block_mut(entry)
            .instructions
            .push(MirInst::CallKfunc {
                dst: release_ret,
                kfunc: "bpf_task_release".to_string(),
                btf_id: None,
                args: vec![VReg(0)],
            });
        subfn.block_mut(entry).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .copied()
            .expect("expected summary");
        assert_eq!(
            summary.kfunc_ref_release_arg_kind(0),
            Some(KfuncRefKind::Task)
        );
        assert_eq!(summary.kfunc_ref_release_arg_kind(1), None);
    }

    #[test]
    fn test_infer_summary_requires_kfunc_ref_release_on_all_returns() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        let release = subfn.alloc_block();
        let done = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;
        subfn.vreg_count = 2;
        subfn.block_mut(entry).terminator = MirInst::Branch {
            cond: VReg(1),
            if_true: release,
            if_false: done,
        };
        let release_ret = subfn.alloc_vreg();
        subfn
            .block_mut(release)
            .instructions
            .push(MirInst::CallKfunc {
                dst: release_ret,
                kfunc: "bpf_task_release".to_string(),
                btf_id: None,
                args: vec![VReg(0)],
            });
        subfn.block_mut(release).terminator = MirInst::Return { val: None };
        subfn.block_mut(done).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .copied()
            .expect("expected summary");
        assert_eq!(summary.kfunc_ref_release_arg_kind(0), None);
    }

    #[test]
    fn test_infer_summary_tracks_kfunc_ref_return() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;
        subfn.vreg_count = 1;
        let acquired = subfn.alloc_vreg();
        subfn
            .block_mut(entry)
            .instructions
            .push(MirInst::CallKfunc {
                dst: acquired,
                kfunc: "bpf_task_acquire".to_string(),
                btf_id: None,
                args: vec![VReg(0)],
            });
        subfn.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(acquired)),
        };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .copied()
            .expect("expected summary");
        assert_eq!(summary.kfunc_ref_return_kind(), Some(KfuncRefKind::Task));
    }

    #[test]
    fn test_infer_summary_requires_kfunc_ref_return_on_all_returns() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        let acquire = subfn.alloc_block();
        let done = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;
        subfn.vreg_count = 2;
        subfn.block_mut(entry).terminator = MirInst::Branch {
            cond: VReg(1),
            if_true: acquire,
            if_false: done,
        };
        let acquired = subfn.alloc_vreg();
        subfn
            .block_mut(acquire)
            .instructions
            .push(MirInst::CallKfunc {
                dst: acquired,
                kfunc: "bpf_task_acquire".to_string(),
                btf_id: None,
                args: vec![VReg(0)],
            });
        subfn.block_mut(acquire).terminator = MirInst::Return {
            val: Some(MirValue::VReg(acquired)),
        };
        subfn.block_mut(done).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .copied()
            .expect("expected summary");
        assert_eq!(summary.kfunc_ref_return_kind(), None);
    }

    #[test]
    fn test_infer_summary_does_not_return_released_kfunc_ref() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;
        subfn.vreg_count = 1;
        let acquired = subfn.alloc_vreg();
        let release_ret = subfn.alloc_vreg();
        subfn
            .block_mut(entry)
            .instructions
            .push(MirInst::CallKfunc {
                dst: acquired,
                kfunc: "bpf_task_acquire".to_string(),
                btf_id: None,
                args: vec![VReg(0)],
            });
        subfn
            .block_mut(entry)
            .instructions
            .push(MirInst::CallKfunc {
                dst: release_ret,
                kfunc: "bpf_task_release".to_string(),
                btf_id: None,
                args: vec![acquired],
            });
        subfn.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(acquired)),
        };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .copied()
            .expect("expected summary");
        assert_eq!(summary.kfunc_ref_return_kind(), None);
    }
}
