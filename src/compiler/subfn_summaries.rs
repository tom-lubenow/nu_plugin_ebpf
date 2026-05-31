use std::collections::{HashMap, HashSet, VecDeque};

use super::instruction::{
    BpfHelper, HelperDynptrArgRole, KfuncIterFamily, KfuncIterLifecycleOp, KfuncRefKind,
    KfuncUnknownDynptrArgRole, KfuncUnknownStackObjectLifecycleOp, helper_acquire_ref_kind,
    helper_release_ref_kind, kfunc_acquire_ref_kind, kfunc_iter_lifecycle,
    kfunc_release_ref_arg_index, kfunc_release_ref_kind, kfunc_unknown_dynptr_args,
    kfunc_unknown_dynptr_copy, kfunc_unknown_stack_object_copy,
    kfunc_unknown_stack_object_lifecycle,
};
use super::mir::{
    BlockId, CtxField, MapRef, MirFunction, MirInst, MirValue, ScalarValueRange, SubfunctionId,
    VReg,
};

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
pub(crate) struct SubfunctionIterDelta {
    pub(crate) family: KfuncIterFamily,
    pub(crate) delta: i8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IterDeltaState {
    family: Option<KfuncIterFamily>,
    delta: i8,
}

impl IterDeltaState {
    const ZERO: Self = Self {
        family: None,
        delta: 0,
    };

    fn add(self, family: KfuncIterFamily, delta: i8) -> Option<Self> {
        let next_delta = self.delta.checked_add(delta)?;
        if next_delta == 0 {
            return Some(Self::ZERO);
        }
        match self.family {
            None => Some(Self {
                family: Some(family),
                delta: next_delta,
            }),
            Some(existing_family) if existing_family == family => Some(Self {
                family: Some(family),
                delta: next_delta,
            }),
            Some(_) => None,
        }
    }

    fn to_summary(self) -> Option<SubfunctionIterDelta> {
        if self.delta == 0 {
            return None;
        }
        self.family.map(|family| SubfunctionIterDelta {
            family,
            delta: self.delta,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubfunctionUnknownStackObjectType {
    pub(crate) type_name: String,
    pub(crate) type_id: Option<u32>,
}

impl SubfunctionUnknownStackObjectType {
    fn new(type_name: impl Into<String>, type_id: Option<u32>) -> Self {
        Self {
            type_name: type_name.into(),
            type_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubfunctionUnknownStackObjectDelta {
    pub(crate) object_type: SubfunctionUnknownStackObjectType,
    pub(crate) delta: i8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubfunctionMapValueMapFdRequirement {
    pub(crate) map_value: SubfunctionMapSource,
    pub(crate) map_fd: SubfunctionMapSource,
    pub(crate) call: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SubfunctionMapSource {
    Arg(usize),
    Map(MapRef),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnknownStackObjectDeltaState {
    object_type: Option<SubfunctionUnknownStackObjectType>,
    delta: i8,
}

impl UnknownStackObjectDeltaState {
    fn zero() -> Self {
        Self {
            object_type: None,
            delta: 0,
        }
    }

    fn add(self, object_type: SubfunctionUnknownStackObjectType, delta: i8) -> Option<Self> {
        let next_delta = self.delta.checked_add(delta)?;
        if next_delta == 0 {
            return Some(Self::zero());
        }
        match self.object_type {
            None => Some(Self {
                object_type: Some(object_type),
                delta: next_delta,
            }),
            Some(existing_type) if existing_type == object_type => Some(Self {
                object_type: Some(object_type),
                delta: next_delta,
            }),
            Some(_) => None,
        }
    }

    fn to_summary(&self) -> Option<SubfunctionUnknownStackObjectDelta> {
        if self.delta == 0 {
            return None;
        }
        self.object_type
            .clone()
            .map(|object_type| SubfunctionUnknownStackObjectDelta {
                object_type,
                delta: self.delta,
            })
    }

    fn maybe_initialized_type(&self) -> Option<SubfunctionUnknownStackObjectType> {
        self.object_type.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubfunctionSummary {
    return_summary: SubfunctionReturnSummary,
    required_return_range: Option<ScalarValueRange>,
    context_field_return: Option<CtxField>,
    ringbuf_record_return: bool,
    kfunc_ref_return_kind: Option<KfuncRefKind>,
    rcu_read_lock_delta: i8,
    preempt_disable_delta: i8,
    local_irq_deltas: [i8; SUMMARY_ARG_SLOTS],
    iter_deltas: [Option<SubfunctionIterDelta>; SUMMARY_ARG_SLOTS],
    dynptr_required_args: u8,
    dynptr_deltas: [i8; SUMMARY_ARG_SLOTS],
    dynptr_maybe_initialized_args: u8,
    unknown_stack_object_required: [Option<SubfunctionUnknownStackObjectType>; SUMMARY_ARG_SLOTS],
    unknown_stack_object_deltas: [Option<SubfunctionUnknownStackObjectDelta>; SUMMARY_ARG_SLOTS],
    unknown_stack_object_maybe_initialized:
        [Option<SubfunctionUnknownStackObjectType>; SUMMARY_ARG_SLOTS],
    map_value_map_fd_requirements: Vec<SubfunctionMapValueMapFdRequirement>,
    ringbuf_record_release_args: u8,
    ringbuf_dynptr_deltas: [i8; SUMMARY_ARG_SLOTS],
    kfunc_ref_release_args: [Option<KfuncRefKind>; SUMMARY_ARG_SLOTS],
}

impl SubfunctionSummary {
    pub(crate) fn unknown() -> Self {
        Self {
            return_summary: SubfunctionReturnSummary::Unknown,
            required_return_range: None,
            context_field_return: None,
            ringbuf_record_return: false,
            kfunc_ref_return_kind: None,
            rcu_read_lock_delta: 0,
            preempt_disable_delta: 0,
            local_irq_deltas: [0; SUMMARY_ARG_SLOTS],
            iter_deltas: [None; SUMMARY_ARG_SLOTS],
            dynptr_required_args: 0,
            dynptr_deltas: [0; SUMMARY_ARG_SLOTS],
            dynptr_maybe_initialized_args: 0,
            unknown_stack_object_required: std::array::from_fn(|_| None),
            unknown_stack_object_deltas: std::array::from_fn(|_| None),
            unknown_stack_object_maybe_initialized: std::array::from_fn(|_| None),
            map_value_map_fd_requirements: Vec::new(),
            ringbuf_record_release_args: 0,
            ringbuf_dynptr_deltas: [0; SUMMARY_ARG_SLOTS],
            kfunc_ref_release_args: [None; SUMMARY_ARG_SLOTS],
        }
    }

    pub(crate) fn from_return_summary(return_summary: SubfunctionReturnSummary) -> Self {
        Self {
            return_summary,
            required_return_range: None,
            context_field_return: None,
            ringbuf_record_return: false,
            kfunc_ref_return_kind: None,
            rcu_read_lock_delta: 0,
            preempt_disable_delta: 0,
            local_irq_deltas: [0; SUMMARY_ARG_SLOTS],
            iter_deltas: [None; SUMMARY_ARG_SLOTS],
            dynptr_required_args: 0,
            dynptr_deltas: [0; SUMMARY_ARG_SLOTS],
            dynptr_maybe_initialized_args: 0,
            unknown_stack_object_required: std::array::from_fn(|_| None),
            unknown_stack_object_deltas: std::array::from_fn(|_| None),
            unknown_stack_object_maybe_initialized: std::array::from_fn(|_| None),
            map_value_map_fd_requirements: Vec::new(),
            ringbuf_record_release_args: 0,
            ringbuf_dynptr_deltas: [0; SUMMARY_ARG_SLOTS],
            kfunc_ref_release_args: [None; SUMMARY_ARG_SLOTS],
        }
    }

    pub(crate) const fn return_summary(&self) -> SubfunctionReturnSummary {
        self.return_summary
    }

    pub(crate) const fn return_arg(&self) -> Option<usize> {
        self.return_summary.return_arg()
    }

    pub(crate) const fn required_return_range(&self) -> Option<ScalarValueRange> {
        self.required_return_range
    }

    pub(crate) fn return_context_field(&self) -> Option<&CtxField> {
        self.context_field_return.as_ref()
    }

    pub(crate) const fn returns_ringbuf_record(&self) -> bool {
        self.ringbuf_record_return
    }

    pub(crate) const fn kfunc_ref_return_kind(&self) -> Option<KfuncRefKind> {
        self.kfunc_ref_return_kind
    }

    pub(crate) const fn rcu_read_lock_delta(&self) -> i8 {
        self.rcu_read_lock_delta
    }

    pub(crate) const fn preempt_disable_delta(&self) -> i8 {
        self.preempt_disable_delta
    }

    pub(crate) const fn local_irq_delta_arg(&self, idx: usize) -> i8 {
        if idx < SUMMARY_ARG_SLOTS {
            self.local_irq_deltas[idx]
        } else {
            0
        }
    }

    pub(crate) const fn iter_delta_arg(&self, idx: usize) -> Option<SubfunctionIterDelta> {
        if idx < SUMMARY_ARG_SLOTS {
            self.iter_deltas[idx]
        } else {
            None
        }
    }

    pub(crate) const fn requires_initialized_dynptr_arg(&self, idx: usize) -> bool {
        idx < 8 && (self.dynptr_required_args & (1 << idx)) != 0
    }

    pub(crate) const fn dynptr_delta_arg(&self, idx: usize) -> i8 {
        if idx < SUMMARY_ARG_SLOTS {
            self.dynptr_deltas[idx]
        } else {
            0
        }
    }

    pub(crate) const fn maybe_initializes_dynptr_arg(&self, idx: usize) -> bool {
        idx < 8 && (self.dynptr_maybe_initialized_args & (1 << idx)) != 0
    }

    pub(crate) fn unknown_stack_object_required_arg(
        &self,
        idx: usize,
    ) -> Option<&SubfunctionUnknownStackObjectType> {
        self.unknown_stack_object_required
            .get(idx)
            .and_then(Option::as_ref)
    }

    pub(crate) fn unknown_stack_object_delta_arg(
        &self,
        idx: usize,
    ) -> Option<&SubfunctionUnknownStackObjectDelta> {
        self.unknown_stack_object_deltas
            .get(idx)
            .and_then(Option::as_ref)
    }

    pub(crate) fn unknown_stack_object_maybe_initialized_arg(
        &self,
        idx: usize,
    ) -> Option<&SubfunctionUnknownStackObjectType> {
        self.unknown_stack_object_maybe_initialized
            .get(idx)
            .and_then(Option::as_ref)
    }

    pub(crate) fn map_value_map_fd_requirements(&self) -> &[SubfunctionMapValueMapFdRequirement] {
        &self.map_value_map_fd_requirements
    }

    pub(crate) const fn changes_packet_data(&self) -> bool {
        self.return_summary.changes_packet_data()
    }

    pub(crate) const fn releases_ringbuf_record_arg(&self, idx: usize) -> bool {
        idx < 8 && (self.ringbuf_record_release_args & (1 << idx)) != 0
    }

    pub(crate) const fn ringbuf_dynptr_delta_arg(&self, idx: usize) -> i8 {
        if idx < SUMMARY_ARG_SLOTS {
            self.ringbuf_dynptr_deltas[idx]
        } else {
            0
        }
    }

    pub(crate) const fn releases_ringbuf_dynptr_arg(&self, idx: usize) -> bool {
        self.ringbuf_dynptr_delta_arg(idx) < 0
    }

    pub(crate) const fn kfunc_ref_release_arg_kind(&self, idx: usize) -> Option<KfuncRefKind> {
        if idx < SUMMARY_ARG_SLOTS {
            self.kfunc_ref_release_args[idx]
        } else {
            None
        }
    }

    fn from_parts(
        return_arg: Option<usize>,
        required_return_range: Option<ScalarValueRange>,
        context_field_return: Option<CtxField>,
        ringbuf_record_return: bool,
        kfunc_ref_return_kind: Option<KfuncRefKind>,
        rcu_read_lock_delta: i8,
        preempt_disable_delta: i8,
        local_irq_deltas: [i8; SUMMARY_ARG_SLOTS],
        iter_deltas: [Option<SubfunctionIterDelta>; SUMMARY_ARG_SLOTS],
        dynptr_required_args: u8,
        dynptr_deltas: [i8; SUMMARY_ARG_SLOTS],
        dynptr_maybe_initialized_args: u8,
        unknown_stack_object_required: [Option<SubfunctionUnknownStackObjectType>;
            SUMMARY_ARG_SLOTS],
        unknown_stack_object_deltas: [Option<SubfunctionUnknownStackObjectDelta>;
            SUMMARY_ARG_SLOTS],
        unknown_stack_object_maybe_initialized: [Option<SubfunctionUnknownStackObjectType>;
            SUMMARY_ARG_SLOTS],
        map_value_map_fd_requirements: Vec<SubfunctionMapValueMapFdRequirement>,
        changes_packet_data: bool,
        ringbuf_record_release_args: u8,
        ringbuf_dynptr_deltas: [i8; SUMMARY_ARG_SLOTS],
        kfunc_ref_release_args: [Option<KfuncRefKind>; SUMMARY_ARG_SLOTS],
    ) -> Self {
        Self {
            return_summary: SubfunctionReturnSummary::from_parts(return_arg, changes_packet_data),
            required_return_range,
            context_field_return,
            ringbuf_record_return,
            kfunc_ref_return_kind,
            rcu_read_lock_delta,
            preempt_disable_delta,
            local_irq_deltas,
            iter_deltas,
            dynptr_required_args,
            dynptr_deltas,
            dynptr_maybe_initialized_args,
            unknown_stack_object_required,
            unknown_stack_object_deltas,
            unknown_stack_object_maybe_initialized,
            map_value_map_fd_requirements,
            ringbuf_record_release_args,
            ringbuf_dynptr_deltas,
            kfunc_ref_release_args,
        }
    }
}

impl From<SubfunctionReturnSummary> for SubfunctionSummary {
    fn from(return_summary: SubfunctionReturnSummary) -> Self {
        Self::from_return_summary(return_summary)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AliasSource {
    Unknown,
    Param(usize),
    ContextField(CtxField),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KfuncRefSource {
    id: VReg,
    kind: KfuncRefKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SummaryMapSource {
    Param(usize),
    Map(MapRef),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SummaryState {
    aliases: Vec<AliasSource>,
    ringbuf_record_sources: Vec<Option<VReg>>,
    kfunc_ref_sources: Vec<Option<KfuncRefSource>>,
    map_value_sources: Vec<Option<SummaryMapSource>>,
    map_fd_sources: Vec<Option<MapRef>>,
    rcu_read_lock_delta: Option<i8>,
    preempt_disable_delta: Option<i8>,
    local_irq_deltas: [Option<i8>; SUMMARY_ARG_SLOTS],
    iter_deltas: [Option<IterDeltaState>; SUMMARY_ARG_SLOTS],
    dynptr_required_args: u8,
    dynptr_deltas: [Option<i8>; SUMMARY_ARG_SLOTS],
    dynptr_maybe_initialized_args: u8,
    unknown_stack_object_required: [Option<SubfunctionUnknownStackObjectType>; SUMMARY_ARG_SLOTS],
    unknown_stack_object_deltas: [Option<UnknownStackObjectDeltaState>; SUMMARY_ARG_SLOTS],
    unknown_stack_object_maybe_initialized:
        [Option<SubfunctionUnknownStackObjectType>; SUMMARY_ARG_SLOTS],
    map_value_map_fd_requirements: Vec<SubfunctionMapValueMapFdRequirement>,
    ringbuf_record_release_args: u8,
    ringbuf_dynptr_deltas: [Option<i8>; SUMMARY_ARG_SLOTS],
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
        return summary.clone();
    }

    if !visiting.insert(subfn) {
        return SubfunctionSummary::unknown();
    }

    let summary = subfunctions
        .get(subfn.0 as usize)
        .map(|func| summarize_function(func, subfunctions, summaries, visiting))
        .unwrap_or_else(SubfunctionSummary::unknown);
    visiting.remove(&subfn);
    summaries.insert(subfn, summary.clone());
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
            ringbuf_record_sources: vec![None; total_vregs],
            kfunc_ref_sources: vec![None; total_vregs],
            map_value_sources: vec![None; total_vregs],
            map_fd_sources: vec![None; total_vregs],
            rcu_read_lock_delta: Some(0),
            preempt_disable_delta: Some(0),
            local_irq_deltas: [Some(0); SUMMARY_ARG_SLOTS],
            iter_deltas: [Some(IterDeltaState::ZERO); SUMMARY_ARG_SLOTS],
            dynptr_required_args: 0,
            dynptr_deltas: [Some(0); SUMMARY_ARG_SLOTS],
            dynptr_maybe_initialized_args: 0,
            unknown_stack_object_required: std::array::from_fn(|_| None),
            unknown_stack_object_deltas: std::array::from_fn(|_| {
                Some(UnknownStackObjectDeltaState::zero())
            }),
            unknown_stack_object_maybe_initialized: std::array::from_fn(|_| None),
            map_value_map_fd_requirements: Vec::new(),
            ringbuf_record_release_args: 0,
            ringbuf_dynptr_deltas: [Some(0); SUMMARY_ARG_SLOTS],
            kfunc_ref_release_args: [None; SUMMARY_ARG_SLOTS],
        },
    );
    worklist.push_back(func.entry);

    let mut return_alias: Option<Option<AliasSource>> = None;
    let mut returned_ringbuf_record: Option<bool> = None;
    let mut returned_kfunc_ref: Option<Option<KfuncRefKind>> = None;
    let mut returned_rcu_delta: Option<Option<i8>> = None;
    let mut returned_preempt_delta: Option<Option<i8>> = None;
    let mut returned_local_irq_deltas: Option<[Option<i8>; SUMMARY_ARG_SLOTS]> = None;
    let mut returned_iter_deltas: Option<[Option<IterDeltaState>; SUMMARY_ARG_SLOTS]> = None;
    let mut returned_dynptr_required: Option<u8> = None;
    let mut returned_dynptr_deltas: Option<[Option<i8>; SUMMARY_ARG_SLOTS]> = None;
    let mut returned_dynptr_maybe_initialized: Option<u8> = None;
    let mut returned_unknown_stack_object_required: Option<
        [Option<SubfunctionUnknownStackObjectType>; SUMMARY_ARG_SLOTS],
    > = None;
    let mut returned_unknown_stack_object_deltas: Option<
        [Option<UnknownStackObjectDeltaState>; SUMMARY_ARG_SLOTS],
    > = None;
    let mut returned_unknown_stack_object_maybe_initialized: Option<
        [Option<SubfunctionUnknownStackObjectType>; SUMMARY_ARG_SLOTS],
    > = None;
    let mut returned_map_value_map_fd_requirements: Option<
        Vec<SubfunctionMapValueMapFdRequirement>,
    > = None;
    let mut changes_packet_data = false;
    let mut returned_record_releases: Option<u8> = None;
    let mut returned_ringbuf_dynptr_deltas: Option<[Option<i8>; SUMMARY_ARG_SLOTS]> = None;
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
                let returns_record = ringbuf_record_return_for_value(val.as_ref(), &state);
                returned_ringbuf_record = Some(match returned_ringbuf_record {
                    None => returns_record,
                    Some(existing) => existing && returns_record,
                });
                let returned_ref = kfunc_ref_return_kind_for_value(val.as_ref(), &state);
                returned_kfunc_ref = match returned_kfunc_ref {
                    None => Some(returned_ref),
                    Some(existing) if existing == returned_ref => Some(existing),
                    Some(_) => Some(None),
                };
                returned_rcu_delta = match returned_rcu_delta {
                    None => Some(state.rcu_read_lock_delta),
                    Some(existing) if existing == state.rcu_read_lock_delta => Some(existing),
                    Some(_) => Some(None),
                };
                returned_preempt_delta = match returned_preempt_delta {
                    None => Some(state.preempt_disable_delta),
                    Some(existing) if existing == state.preempt_disable_delta => Some(existing),
                    Some(_) => Some(None),
                };
                returned_local_irq_deltas = Some(match returned_local_irq_deltas {
                    None => state.local_irq_deltas,
                    Some(existing) => merge_delta_args(existing, state.local_irq_deltas),
                });
                returned_iter_deltas = Some(match returned_iter_deltas {
                    None => state.iter_deltas,
                    Some(existing) => merge_iter_delta_args(existing, state.iter_deltas),
                });
                returned_dynptr_required = Some(match returned_dynptr_required {
                    None => state.dynptr_required_args,
                    Some(existing) => existing | state.dynptr_required_args,
                });
                returned_dynptr_deltas = Some(match returned_dynptr_deltas {
                    None => state.dynptr_deltas,
                    Some(existing) => merge_delta_args(existing, state.dynptr_deltas),
                });
                returned_dynptr_maybe_initialized = Some(match returned_dynptr_maybe_initialized {
                    None => state.dynptr_maybe_initialized_args,
                    Some(existing) => existing | state.dynptr_maybe_initialized_args,
                });
                returned_unknown_stack_object_required =
                    Some(match returned_unknown_stack_object_required {
                        None => state.unknown_stack_object_required.clone(),
                        Some(existing) => merge_unknown_stack_object_required_args(
                            existing,
                            state.unknown_stack_object_required.clone(),
                        ),
                    });
                returned_unknown_stack_object_deltas =
                    Some(match returned_unknown_stack_object_deltas {
                        None => state.unknown_stack_object_deltas.clone(),
                        Some(existing) => {
                            let mut maybe = returned_unknown_stack_object_maybe_initialized
                                .clone()
                                .unwrap_or_else(|| std::array::from_fn(|_| None));
                            let merged = merge_unknown_stack_object_delta_args(
                                existing,
                                state.unknown_stack_object_deltas.clone(),
                                &mut maybe,
                            );
                            returned_unknown_stack_object_maybe_initialized = Some(maybe);
                            merged
                        }
                    });
                returned_unknown_stack_object_maybe_initialized =
                    Some(match returned_unknown_stack_object_maybe_initialized {
                        None => state.unknown_stack_object_maybe_initialized.clone(),
                        Some(existing) => merge_unknown_stack_object_required_args(
                            existing,
                            state.unknown_stack_object_maybe_initialized.clone(),
                        ),
                    });
                returned_map_value_map_fd_requirements =
                    Some(match returned_map_value_map_fd_requirements.take() {
                        None => state.map_value_map_fd_requirements.clone(),
                        Some(mut existing) => {
                            extend_unique_requirements(
                                &mut existing,
                                &state.map_value_map_fd_requirements,
                            );
                            existing
                        }
                    });
                returned_record_releases = Some(match returned_record_releases {
                    None => state.ringbuf_record_release_args,
                    Some(existing) => existing & state.ringbuf_record_release_args,
                });
                returned_ringbuf_dynptr_deltas = Some(match returned_ringbuf_dynptr_deltas {
                    None => state.ringbuf_dynptr_deltas,
                    Some(existing) => merge_delta_args(existing, state.ringbuf_dynptr_deltas),
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

    let dynptr_maybe_initialized_args = returned_dynptr_maybe_initialized.unwrap_or(0)
        | inconsistent_delta_args(returned_dynptr_deltas);
    let unknown_stack_object_maybe_initialized = returned_unknown_stack_object_maybe_initialized
        .unwrap_or_else(|| std::array::from_fn(|_| None));

    let return_alias = return_alias.flatten();
    let return_arg = match &return_alias {
        Some(AliasSource::Param(idx)) => Some(*idx),
        _ => None,
    };
    let context_field_return = match return_alias {
        Some(AliasSource::ContextField(field)) => Some(field),
        _ => None,
    };

    SubfunctionSummary::from_parts(
        return_arg,
        func.required_return_range,
        context_field_return,
        returned_ringbuf_record.unwrap_or(false),
        returned_kfunc_ref.flatten(),
        returned_rcu_delta.flatten().unwrap_or(0),
        returned_preempt_delta.flatten().unwrap_or(0),
        finalize_delta_args(returned_local_irq_deltas),
        finalize_iter_delta_args(returned_iter_deltas),
        returned_dynptr_required.unwrap_or(0),
        finalize_delta_args(returned_dynptr_deltas),
        dynptr_maybe_initialized_args,
        returned_unknown_stack_object_required.unwrap_or_else(|| std::array::from_fn(|_| None)),
        finalize_unknown_stack_object_delta_args(returned_unknown_stack_object_deltas),
        unknown_stack_object_maybe_initialized,
        returned_map_value_map_fd_requirements.unwrap_or_default(),
        changes_packet_data,
        returned_record_releases.unwrap_or(0),
        finalize_delta_args(returned_ringbuf_dynptr_deltas),
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
        .zip(incoming.aliases.iter().cloned())
    {
        let merged = match (&*dst, src) {
            (AliasSource::Param(lhs), AliasSource::Param(rhs)) if *lhs == rhs => dst.clone(),
            (AliasSource::ContextField(lhs), AliasSource::ContextField(rhs)) if *lhs == rhs => {
                dst.clone()
            }
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
    for (dst, src) in existing
        .ringbuf_record_sources
        .iter_mut()
        .zip(incoming.ringbuf_record_sources.iter().copied())
    {
        let merged = if *dst == src { *dst } else { None };
        if *dst != merged {
            *dst = merged;
            changed = true;
        }
    }
    for (dst, src) in existing
        .map_value_sources
        .iter_mut()
        .zip(incoming.map_value_sources.iter().cloned())
    {
        let merged = if *dst == src { (*dst).clone() } else { None };
        if *dst != merged {
            *dst = merged;
            changed = true;
        }
    }
    for (dst, src) in existing
        .map_fd_sources
        .iter_mut()
        .zip(incoming.map_fd_sources.iter().cloned())
    {
        let merged = if *dst == src { (*dst).clone() } else { None };
        if *dst != merged {
            *dst = merged;
            changed = true;
        }
    }
    let rcu_delta = merge_delta(existing.rcu_read_lock_delta, incoming.rcu_read_lock_delta);
    if existing.rcu_read_lock_delta != rcu_delta {
        existing.rcu_read_lock_delta = rcu_delta;
        changed = true;
    }
    let preempt_delta = merge_delta(
        existing.preempt_disable_delta,
        incoming.preempt_disable_delta,
    );
    if existing.preempt_disable_delta != preempt_delta {
        existing.preempt_disable_delta = preempt_delta;
        changed = true;
    }
    let local_irq_deltas = merge_delta_args(existing.local_irq_deltas, incoming.local_irq_deltas);
    if existing.local_irq_deltas != local_irq_deltas {
        existing.local_irq_deltas = local_irq_deltas;
        changed = true;
    }
    let iter_deltas = merge_iter_delta_args(existing.iter_deltas, incoming.iter_deltas);
    if existing.iter_deltas != iter_deltas {
        existing.iter_deltas = iter_deltas;
        changed = true;
    }
    let dynptr_required_args = existing.dynptr_required_args | incoming.dynptr_required_args;
    if existing.dynptr_required_args != dynptr_required_args {
        existing.dynptr_required_args = dynptr_required_args;
        changed = true;
    }
    let dynptr_deltas = merge_delta_args(existing.dynptr_deltas, incoming.dynptr_deltas);
    if existing.dynptr_deltas != dynptr_deltas {
        existing.dynptr_deltas = dynptr_deltas;
        changed = true;
    }
    let dynptr_maybe_initialized_args =
        existing.dynptr_maybe_initialized_args | incoming.dynptr_maybe_initialized_args;
    if existing.dynptr_maybe_initialized_args != dynptr_maybe_initialized_args {
        existing.dynptr_maybe_initialized_args = dynptr_maybe_initialized_args;
        changed = true;
    }
    let unknown_stack_object_required = merge_unknown_stack_object_required_args(
        existing.unknown_stack_object_required.clone(),
        incoming.unknown_stack_object_required.clone(),
    );
    if existing.unknown_stack_object_required != unknown_stack_object_required {
        existing.unknown_stack_object_required = unknown_stack_object_required;
        changed = true;
    }
    let mut unknown_stack_object_maybe_initialized = merge_unknown_stack_object_required_args(
        existing.unknown_stack_object_maybe_initialized.clone(),
        incoming.unknown_stack_object_maybe_initialized.clone(),
    );
    let unknown_stack_object_deltas = merge_unknown_stack_object_delta_args(
        existing.unknown_stack_object_deltas.clone(),
        incoming.unknown_stack_object_deltas.clone(),
        &mut unknown_stack_object_maybe_initialized,
    );
    if existing.unknown_stack_object_deltas != unknown_stack_object_deltas {
        existing.unknown_stack_object_deltas = unknown_stack_object_deltas;
        changed = true;
    }
    if existing.unknown_stack_object_maybe_initialized != unknown_stack_object_maybe_initialized {
        existing.unknown_stack_object_maybe_initialized = unknown_stack_object_maybe_initialized;
        changed = true;
    }
    let old_len = existing.map_value_map_fd_requirements.len();
    extend_unique_requirements(
        &mut existing.map_value_map_fd_requirements,
        &incoming.map_value_map_fd_requirements,
    );
    if existing.map_value_map_fd_requirements.len() != old_len {
        changed = true;
    }
    let record_releases =
        existing.ringbuf_record_release_args & incoming.ringbuf_record_release_args;
    if existing.ringbuf_record_release_args != record_releases {
        existing.ringbuf_record_release_args = record_releases;
        changed = true;
    }
    let dynptr_deltas = merge_delta_args(
        existing.ringbuf_dynptr_deltas,
        incoming.ringbuf_dynptr_deltas,
    );
    if existing.ringbuf_dynptr_deltas != dynptr_deltas {
        existing.ringbuf_dynptr_deltas = dynptr_deltas;
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

fn merge_delta(existing: Option<i8>, incoming: Option<i8>) -> Option<i8> {
    if existing == incoming { existing } else { None }
}

fn extend_unique_requirements(
    requirements: &mut Vec<SubfunctionMapValueMapFdRequirement>,
    incoming: &[SubfunctionMapValueMapFdRequirement],
) {
    for requirement in incoming {
        if !requirements.contains(requirement) {
            requirements.push(requirement.clone());
        }
    }
}

fn merge_delta_args(
    existing: [Option<i8>; SUMMARY_ARG_SLOTS],
    incoming: [Option<i8>; SUMMARY_ARG_SLOTS],
) -> [Option<i8>; SUMMARY_ARG_SLOTS] {
    let mut merged = [None; SUMMARY_ARG_SLOTS];
    for idx in 0..SUMMARY_ARG_SLOTS {
        merged[idx] = merge_delta(existing[idx], incoming[idx]);
    }
    merged
}

fn finalize_delta_args(
    returned: Option<[Option<i8>; SUMMARY_ARG_SLOTS]>,
) -> [i8; SUMMARY_ARG_SLOTS] {
    let Some(returned) = returned else {
        return [0; SUMMARY_ARG_SLOTS];
    };
    let mut finalized = [0; SUMMARY_ARG_SLOTS];
    for idx in 0..SUMMARY_ARG_SLOTS {
        finalized[idx] = returned[idx].unwrap_or(0);
    }
    finalized
}

fn inconsistent_delta_args(returned: Option<[Option<i8>; SUMMARY_ARG_SLOTS]>) -> u8 {
    let Some(returned) = returned else {
        return 0;
    };
    let mut args = 0;
    for (idx, delta) in returned.iter().enumerate() {
        if delta.is_none() {
            set_mask_bit(&mut args, idx);
        }
    }
    args
}

fn merge_iter_delta_args(
    existing: [Option<IterDeltaState>; SUMMARY_ARG_SLOTS],
    incoming: [Option<IterDeltaState>; SUMMARY_ARG_SLOTS],
) -> [Option<IterDeltaState>; SUMMARY_ARG_SLOTS] {
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

fn finalize_iter_delta_args(
    returned: Option<[Option<IterDeltaState>; SUMMARY_ARG_SLOTS]>,
) -> [Option<SubfunctionIterDelta>; SUMMARY_ARG_SLOTS] {
    let Some(returned) = returned else {
        return [None; SUMMARY_ARG_SLOTS];
    };
    let mut finalized = [None; SUMMARY_ARG_SLOTS];
    for idx in 0..SUMMARY_ARG_SLOTS {
        finalized[idx] = returned[idx].and_then(IterDeltaState::to_summary);
    }
    finalized
}

fn merge_unknown_stack_object_required_args(
    existing: [Option<SubfunctionUnknownStackObjectType>; SUMMARY_ARG_SLOTS],
    incoming: [Option<SubfunctionUnknownStackObjectType>; SUMMARY_ARG_SLOTS],
) -> [Option<SubfunctionUnknownStackObjectType>; SUMMARY_ARG_SLOTS] {
    std::array::from_fn(|idx| {
        merge_unknown_stack_object_type_option(existing[idx].clone(), incoming[idx].clone())
    })
}

fn merge_unknown_stack_object_type_option(
    existing: Option<SubfunctionUnknownStackObjectType>,
    incoming: Option<SubfunctionUnknownStackObjectType>,
) -> Option<SubfunctionUnknownStackObjectType> {
    match (existing, incoming) {
        (Some(lhs), Some(rhs)) if lhs == rhs => Some(lhs),
        (Some(lhs), None) => Some(lhs),
        (None, Some(rhs)) => Some(rhs),
        (Some(_), Some(_)) | (None, None) => None,
    }
}

fn merge_unknown_stack_object_delta_args(
    existing: [Option<UnknownStackObjectDeltaState>; SUMMARY_ARG_SLOTS],
    incoming: [Option<UnknownStackObjectDeltaState>; SUMMARY_ARG_SLOTS],
    maybe_initialized: &mut [Option<SubfunctionUnknownStackObjectType>; SUMMARY_ARG_SLOTS],
) -> [Option<UnknownStackObjectDeltaState>; SUMMARY_ARG_SLOTS] {
    std::array::from_fn(|idx| {
        if existing[idx] == incoming[idx] {
            existing[idx].clone()
        } else {
            let maybe_type = existing[idx]
                .as_ref()
                .and_then(UnknownStackObjectDeltaState::maybe_initialized_type)
                .or_else(|| {
                    incoming[idx]
                        .as_ref()
                        .and_then(UnknownStackObjectDeltaState::maybe_initialized_type)
                });
            maybe_initialized[idx] =
                merge_unknown_stack_object_type_option(maybe_initialized[idx].clone(), maybe_type);
            None
        }
    })
}

fn finalize_unknown_stack_object_delta_args(
    returned: Option<[Option<UnknownStackObjectDeltaState>; SUMMARY_ARG_SLOTS]>,
) -> [Option<SubfunctionUnknownStackObjectDelta>; SUMMARY_ARG_SLOTS] {
    let Some(returned) = returned else {
        return std::array::from_fn(|_| None);
    };
    std::array::from_fn(|idx| {
        returned[idx]
            .as_ref()
            .and_then(UnknownStackObjectDeltaState::to_summary)
    })
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
            let ringbuf_record_source = ringbuf_record_source_for_mir_value(src, state);
            set_ringbuf_record_source(
                &mut state.ringbuf_record_sources,
                *dst,
                ringbuf_record_source,
            );
            let kfunc_ref_source = kfunc_ref_source_for_mir_value(src, state);
            set_kfunc_ref_source(&mut state.kfunc_ref_sources, *dst, kfunc_ref_source);
            let map_value_source = map_value_source_for_mir_value(src, state);
            set_map_value_source(&mut state.map_value_sources, *dst, map_value_source);
            let map_fd_source = map_fd_source_for_mir_value(src, state);
            set_map_fd_source(&mut state.map_fd_sources, *dst, map_fd_source);
            InstEffects::default()
        }
        MirInst::Phi { dst, args } => {
            let mut alias = AliasSource::Unknown;
            let mut ringbuf_record_source = None;
            let mut kfunc_ref_source = None;
            let mut map_value_source = None;
            let mut map_fd_source = None;
            let mut first = true;
            for (_, arg) in args {
                let current = get_alias(&state.aliases, *arg);
                let current_record_source = ringbuf_record_source_for_vreg(state, *arg);
                let current_ref_source = kfunc_ref_source_for_vreg(state, *arg);
                let current_map_value_source = map_value_source_for_vreg(state, *arg);
                let current_map_fd_source = map_fd_source_for_vreg(state, *arg);
                if first {
                    alias = current;
                    ringbuf_record_source = current_record_source;
                    kfunc_ref_source = current_ref_source;
                    map_value_source = current_map_value_source.clone();
                    map_fd_source = current_map_fd_source.clone();
                    first = false;
                } else if alias != current {
                    alias = AliasSource::Unknown;
                }
                if !first && ringbuf_record_source != current_record_source {
                    ringbuf_record_source = None;
                }
                if !first && kfunc_ref_source != current_ref_source {
                    kfunc_ref_source = None;
                }
                if !first && map_value_source != current_map_value_source {
                    map_value_source = None;
                }
                if !first && map_fd_source != current_map_fd_source {
                    map_fd_source = None;
                }
            }
            set_alias(&mut state.aliases, *dst, alias);
            set_ringbuf_record_source(
                &mut state.ringbuf_record_sources,
                *dst,
                ringbuf_record_source,
            );
            set_kfunc_ref_source(&mut state.kfunc_ref_sources, *dst, kfunc_ref_source);
            set_map_value_source(&mut state.map_value_sources, *dst, map_value_source);
            set_map_fd_source(&mut state.map_fd_sources, *dst, map_fd_source);
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
                None => summary
                    .return_context_field()
                    .cloned()
                    .map(AliasSource::ContextField)
                    .unwrap_or(AliasSource::Unknown),
            };
            set_alias(&mut state.aliases, *dst, alias);
            let ringbuf_record_source = match summary.return_arg() {
                Some(idx) => args
                    .get(idx)
                    .copied()
                    .and_then(|arg| ringbuf_record_source_for_vreg(state, arg)),
                None if summary.returns_ringbuf_record() => Some(*dst),
                None => None,
            };
            set_ringbuf_record_source(
                &mut state.ringbuf_record_sources,
                *dst,
                ringbuf_record_source,
            );
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
            let map_value_source = summary
                .return_arg()
                .and_then(|idx| args.get(idx).copied())
                .and_then(|arg| map_value_source_for_vreg(state, arg));
            set_map_value_source(&mut state.map_value_sources, *dst, map_value_source);
            let map_fd_source = summary
                .return_arg()
                .and_then(|idx| args.get(idx).copied())
                .and_then(|arg| map_fd_source_for_vreg(state, arg));
            set_map_fd_source(&mut state.map_fd_sources, *dst, map_fd_source);
            apply_subfunction_critical_delta(&summary, args, state);
            apply_subfunction_release_summary(&summary, args, state);
            apply_subfunction_map_value_map_fd_requirements(&summary, args, state);
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
            set_ringbuf_record_source(&mut state.ringbuf_record_sources, *dst, None);
            set_kfunc_ref_source(&mut state.kfunc_ref_sources, *dst, None);
            set_map_value_source(&mut state.map_value_sources, *dst, None);
            set_map_fd_source(&mut state.map_fd_sources, *dst, None);
            InstEffects::default()
        }
        MirInst::CallHelper { dst, helper, args } => {
            set_alias(&mut state.aliases, *dst, AliasSource::Unknown);
            apply_helper_map_value_map_fd_requirement(*helper, args, state, param_stack_aliases);
            apply_helper_release_summary(inst, state, param_stack_aliases);
            let kfunc_ref_source = BpfHelper::from_u32(*helper)
                .and_then(helper_acquire_ref_kind)
                .map(|kind| KfuncRefSource { id: *dst, kind });
            let ringbuf_record_source = matches!(
                BpfHelper::from_u32(*helper),
                Some(BpfHelper::RingbufReserve)
            )
            .then_some(*dst);
            set_ringbuf_record_source(
                &mut state.ringbuf_record_sources,
                *dst,
                ringbuf_record_source,
            );
            set_kfunc_ref_source(&mut state.kfunc_ref_sources, *dst, kfunc_ref_source);
            set_map_value_source(&mut state.map_value_sources, *dst, None);
            set_map_fd_source(&mut state.map_fd_sources, *dst, None);
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
            apply_kfunc_map_value_map_fd_requirement(kfunc, args, state);
            apply_kfunc_release_summary(kfunc, args, state);
            apply_kfunc_critical_delta(kfunc, args, state);
            apply_kfunc_dynptr_summary(kfunc, args, state);
            apply_kfunc_unknown_stack_object_summary(kfunc, args, state);
            let kfunc_ref_source =
                kfunc_acquire_ref_kind(kfunc).map(|kind| KfuncRefSource { id: *dst, kind });
            set_kfunc_ref_source(&mut state.kfunc_ref_sources, *dst, kfunc_ref_source);
            set_map_value_source(&mut state.map_value_sources, *dst, None);
            set_map_fd_source(&mut state.map_fd_sources, *dst, None);
            InstEffects::default()
        }
        MirInst::LoadMapFd { dst, map } => {
            set_alias(&mut state.aliases, *dst, AliasSource::Unknown);
            set_ringbuf_record_source(&mut state.ringbuf_record_sources, *dst, None);
            set_kfunc_ref_source(&mut state.kfunc_ref_sources, *dst, None);
            set_map_value_source(&mut state.map_value_sources, *dst, None);
            set_map_fd_source(&mut state.map_fd_sources, *dst, Some(map.clone()));
            InstEffects::default()
        }
        MirInst::MapLookup { dst, map, .. } => {
            set_alias(&mut state.aliases, *dst, AliasSource::Unknown);
            set_ringbuf_record_source(&mut state.ringbuf_record_sources, *dst, None);
            set_kfunc_ref_source(&mut state.kfunc_ref_sources, *dst, None);
            set_map_value_source(
                &mut state.map_value_sources,
                *dst,
                Some(SummaryMapSource::Map(map.clone())),
            );
            set_map_fd_source(&mut state.map_fd_sources, *dst, None);
            InstEffects::default()
        }
        MirInst::LoadCtxField { dst, field, .. } => {
            set_alias(
                &mut state.aliases,
                *dst,
                AliasSource::ContextField(field.clone()),
            );
            set_ringbuf_record_source(&mut state.ringbuf_record_sources, *dst, None);
            set_kfunc_ref_source(&mut state.kfunc_ref_sources, *dst, None);
            set_map_value_source(&mut state.map_value_sources, *dst, None);
            set_map_fd_source(&mut state.map_fd_sources, *dst, None);
            InstEffects::default()
        }
        MirInst::BinOp { dst, .. }
        | MirInst::UnaryOp { dst, .. }
        | MirInst::LoadSubprogram { dst, .. }
        | MirInst::MapLookupDynamic { dst, .. }
        | MirInst::ListNew { dst, .. }
        | MirInst::ListLen { dst, .. }
        | MirInst::ListGet { dst, .. }
        | MirInst::StopTimer { dst }
        | MirInst::Load { dst, .. }
        | MirInst::LoadSlot { dst, .. }
        | MirInst::StrCmp { dst, .. }
        | MirInst::LoopHeader { counter: dst, .. } => {
            set_alias(&mut state.aliases, *dst, AliasSource::Unknown);
            set_ringbuf_record_source(&mut state.ringbuf_record_sources, *dst, None);
            set_kfunc_ref_source(&mut state.kfunc_ref_sources, *dst, None);
            set_map_value_source(&mut state.map_value_sources, *dst, None);
            set_map_fd_source(&mut state.map_fd_sources, *dst, None);
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

fn apply_subfunction_critical_delta(
    summary: &SubfunctionSummary,
    args: &[VReg],
    state: &mut SummaryState,
) {
    add_delta(
        &mut state.rcu_read_lock_delta,
        summary.rcu_read_lock_delta(),
    );
    add_delta(
        &mut state.preempt_disable_delta,
        summary.preempt_disable_delta(),
    );
    for idx in 0..SUMMARY_ARG_SLOTS {
        let delta = summary.local_irq_delta_arg(idx);
        if delta == 0 {
            continue;
        }
        let Some(arg) = args.get(idx) else {
            continue;
        };
        let AliasSource::Param(param_idx) = get_alias(&state.aliases, *arg) else {
            continue;
        };
        add_delta_arg(&mut state.local_irq_deltas, param_idx, delta);
    }
    for idx in 0..SUMMARY_ARG_SLOTS {
        let Some(delta) = summary.iter_delta_arg(idx) else {
            continue;
        };
        let Some(arg) = args.get(idx) else {
            continue;
        };
        let AliasSource::Param(param_idx) = get_alias(&state.aliases, *arg) else {
            continue;
        };
        add_iter_delta_arg(&mut state.iter_deltas, param_idx, delta.family, delta.delta);
    }
}

fn apply_kfunc_critical_delta(kfunc: &str, args: &[VReg], state: &mut SummaryState) {
    match kfunc {
        "bpf_rcu_read_lock" => add_delta(&mut state.rcu_read_lock_delta, 1),
        "bpf_rcu_read_unlock" => add_delta(&mut state.rcu_read_lock_delta, -1),
        "bpf_preempt_disable" => add_delta(&mut state.preempt_disable_delta, 1),
        "bpf_preempt_enable" => add_delta(&mut state.preempt_disable_delta, -1),
        "bpf_local_irq_save" => apply_local_irq_delta(args, state, 1),
        "bpf_local_irq_restore" => apply_local_irq_delta(args, state, -1),
        _ => apply_kfunc_iter_delta(kfunc, args, state),
    }
}

fn apply_local_irq_delta(args: &[VReg], state: &mut SummaryState, delta: i8) {
    let Some(arg) = args.first() else {
        return;
    };
    let AliasSource::Param(param_idx) = get_alias(&state.aliases, *arg) else {
        return;
    };
    add_delta_arg(&mut state.local_irq_deltas, param_idx, delta);
}

fn add_delta(slot: &mut Option<i8>, delta: i8) {
    *slot = slot.and_then(|value| value.checked_add(delta));
}

fn add_delta_arg(slots: &mut [Option<i8>; SUMMARY_ARG_SLOTS], idx: usize, delta: i8) {
    if let Some(slot) = slots.get_mut(idx) {
        add_delta(slot, delta);
    }
}

fn apply_kfunc_iter_delta(kfunc: &str, args: &[VReg], state: &mut SummaryState) {
    let Some(lifecycle) = kfunc_iter_lifecycle(kfunc) else {
        return;
    };
    let delta = match lifecycle.op {
        KfuncIterLifecycleOp::New => 1,
        KfuncIterLifecycleOp::Destroy => -1,
        KfuncIterLifecycleOp::Next => return,
    };
    let Some(arg) = args.get(lifecycle.arg_idx) else {
        return;
    };
    let AliasSource::Param(param_idx) = get_alias(&state.aliases, *arg) else {
        return;
    };
    add_iter_delta_arg(&mut state.iter_deltas, param_idx, lifecycle.family, delta);
}

fn apply_kfunc_dynptr_summary(kfunc: &str, args: &[VReg], state: &mut SummaryState) {
    let copies = kfunc_unknown_dynptr_copy(kfunc);
    let dynptr_args = kfunc_unknown_dynptr_args(kfunc);
    for dynptr_arg in &dynptr_args {
        let Some(arg) = args.get(dynptr_arg.arg_idx) else {
            continue;
        };
        let AliasSource::Param(param_idx) = get_alias(&state.aliases, *arg) else {
            continue;
        };
        match dynptr_arg.role {
            KfuncUnknownDynptrArgRole::In => {
                set_mask_bit(&mut state.dynptr_required_args, param_idx);
            }
            KfuncUnknownDynptrArgRole::Out => {
                if copies
                    .iter()
                    .any(|copy| copy.dst_arg_idx == dynptr_arg.arg_idx)
                {
                    continue;
                }
                add_delta_arg(&mut state.dynptr_deltas, param_idx, 1);
            }
        }
    }
    for copy in copies {
        if let Some(src) = args.get(copy.src_arg_idx)
            && let AliasSource::Param(param_idx) = get_alias(&state.aliases, *src)
        {
            set_mask_bit(&mut state.dynptr_required_args, param_idx);
            if copy.move_semantics {
                add_delta_arg(&mut state.dynptr_deltas, param_idx, -1);
            }
        }
        if let Some(dst) = args.get(copy.dst_arg_idx)
            && let AliasSource::Param(param_idx) = get_alias(&state.aliases, *dst)
        {
            add_delta_arg(&mut state.dynptr_deltas, param_idx, 1);
        }
    }
}

fn apply_kfunc_unknown_stack_object_summary(kfunc: &str, args: &[VReg], state: &mut SummaryState) {
    let copies = kfunc_unknown_stack_object_copy(kfunc);
    if copies.is_empty()
        && let Some(lifecycle) = kfunc_unknown_stack_object_lifecycle(kfunc)
        && let Some(arg) = args.get(lifecycle.arg_idx)
        && let AliasSource::Param(param_idx) = get_alias(&state.aliases, *arg)
    {
        let object_type =
            SubfunctionUnknownStackObjectType::new(lifecycle.type_name, lifecycle.type_id);
        match lifecycle.op {
            KfuncUnknownStackObjectLifecycleOp::Init => {
                add_unknown_stack_object_delta_arg(
                    &mut state.unknown_stack_object_deltas,
                    param_idx,
                    object_type,
                    1,
                );
            }
            KfuncUnknownStackObjectLifecycleOp::Destroy => {
                set_unknown_stack_object_required_arg(
                    &mut state.unknown_stack_object_required,
                    param_idx,
                    object_type.clone(),
                );
                add_unknown_stack_object_delta_arg(
                    &mut state.unknown_stack_object_deltas,
                    param_idx,
                    object_type,
                    -1,
                );
            }
        }
    }
    for copy in copies {
        let object_type = SubfunctionUnknownStackObjectType::new(copy.type_name, copy.type_id);
        if let Some(src) = args.get(copy.src_arg_idx)
            && let AliasSource::Param(param_idx) = get_alias(&state.aliases, *src)
        {
            set_unknown_stack_object_required_arg(
                &mut state.unknown_stack_object_required,
                param_idx,
                object_type.clone(),
            );
            if copy.move_semantics {
                add_unknown_stack_object_delta_arg(
                    &mut state.unknown_stack_object_deltas,
                    param_idx,
                    object_type.clone(),
                    -1,
                );
            }
        }
        if let Some(dst) = args.get(copy.dst_arg_idx)
            && let AliasSource::Param(param_idx) = get_alias(&state.aliases, *dst)
        {
            add_unknown_stack_object_delta_arg(
                &mut state.unknown_stack_object_deltas,
                param_idx,
                object_type,
                1,
            );
        }
    }
}

fn apply_helper_map_value_map_fd_requirement(
    helper: u32,
    args: &[MirValue],
    state: &mut SummaryState,
    param_stack_aliases: &HashMap<super::mir::StackSlotId, usize>,
) {
    let Some(BpfHelper::TimerInit) = BpfHelper::from_u32(helper) else {
        return;
    };
    let (Some(map_value), Some(map_fd)) = (args.first(), args.get(1)) else {
        return;
    };
    let Some(map_value) =
        map_value_requirement_source_for_mir_value(map_value, state, param_stack_aliases)
    else {
        return;
    };
    let Some(map_fd) = map_fd_requirement_source_for_mir_value(map_fd, state, param_stack_aliases)
    else {
        return;
    };
    record_map_value_map_fd_requirement(state, map_value, map_fd, "helper 'bpf_timer_init'");
}

fn apply_kfunc_map_value_map_fd_requirement(kfunc: &str, args: &[VReg], state: &mut SummaryState) {
    if kfunc != "bpf_wq_init" {
        return;
    }
    let (Some(map_value), Some(map_fd)) = (args.first(), args.get(1)) else {
        return;
    };
    let Some(map_value) = map_value_requirement_source_for_vreg(*map_value, state) else {
        return;
    };
    let Some(map_fd) = map_fd_requirement_source_for_vreg(*map_fd, state) else {
        return;
    };
    record_map_value_map_fd_requirement(state, map_value, map_fd, "kfunc 'bpf_wq_init'");
}

fn apply_subfunction_map_value_map_fd_requirements(
    summary: &SubfunctionSummary,
    args: &[VReg],
    state: &mut SummaryState,
) {
    for requirement in summary.map_value_map_fd_requirements() {
        let Some(map_value) =
            resolve_subfunction_map_value_requirement_source(&requirement.map_value, args, state)
        else {
            continue;
        };
        let Some(map_fd) =
            resolve_subfunction_map_fd_requirement_source(&requirement.map_fd, args, state)
        else {
            continue;
        };
        record_map_value_map_fd_requirement(state, map_value, map_fd, &requirement.call);
    }
}

fn map_value_requirement_source_for_mir_value(
    value: &MirValue,
    state: &SummaryState,
    param_stack_aliases: &HashMap<super::mir::StackSlotId, usize>,
) -> Option<SummaryMapSource> {
    match alias_for_mir_value(value, &state.aliases, param_stack_aliases) {
        AliasSource::Param(idx) => Some(SummaryMapSource::Param(idx)),
        AliasSource::Unknown | AliasSource::ContextField(_) => {
            map_value_source_for_mir_value(value, state)
        }
    }
}

fn map_value_requirement_source_for_vreg(
    value: VReg,
    state: &SummaryState,
) -> Option<SummaryMapSource> {
    match get_alias(&state.aliases, value) {
        AliasSource::Param(idx) => Some(SummaryMapSource::Param(idx)),
        AliasSource::Unknown | AliasSource::ContextField(_) => {
            map_value_source_for_vreg(state, value)
        }
    }
}

fn map_fd_requirement_source_for_mir_value(
    value: &MirValue,
    state: &SummaryState,
    param_stack_aliases: &HashMap<super::mir::StackSlotId, usize>,
) -> Option<SummaryMapSource> {
    match alias_for_mir_value(value, &state.aliases, param_stack_aliases) {
        AliasSource::Param(idx) => Some(SummaryMapSource::Param(idx)),
        AliasSource::Unknown | AliasSource::ContextField(_) => {
            map_fd_source_for_mir_value(value, state).map(SummaryMapSource::Map)
        }
    }
}

fn map_fd_requirement_source_for_vreg(
    value: VReg,
    state: &SummaryState,
) -> Option<SummaryMapSource> {
    match get_alias(&state.aliases, value) {
        AliasSource::Param(idx) => Some(SummaryMapSource::Param(idx)),
        AliasSource::Unknown | AliasSource::ContextField(_) => {
            map_fd_source_for_vreg(state, value).map(SummaryMapSource::Map)
        }
    }
}

fn resolve_subfunction_map_value_requirement_source(
    source: &SubfunctionMapSource,
    args: &[VReg],
    state: &SummaryState,
) -> Option<SummaryMapSource> {
    match source {
        SubfunctionMapSource::Arg(idx) => args
            .get(*idx)
            .copied()
            .and_then(|arg| map_value_requirement_source_for_vreg(arg, state)),
        SubfunctionMapSource::Map(map) => Some(SummaryMapSource::Map(map.clone())),
    }
}

fn resolve_subfunction_map_fd_requirement_source(
    source: &SubfunctionMapSource,
    args: &[VReg],
    state: &SummaryState,
) -> Option<SummaryMapSource> {
    match source {
        SubfunctionMapSource::Arg(idx) => args
            .get(*idx)
            .copied()
            .and_then(|arg| map_fd_requirement_source_for_vreg(arg, state)),
        SubfunctionMapSource::Map(map) => Some(SummaryMapSource::Map(map.clone())),
    }
}

fn record_map_value_map_fd_requirement(
    state: &mut SummaryState,
    map_value: SummaryMapSource,
    map_fd: SummaryMapSource,
    call: &str,
) {
    let Some(map_value) = summary_source_to_requirement(map_value) else {
        return;
    };
    let Some(map_fd) = summary_source_to_requirement(map_fd) else {
        return;
    };
    let requirement = SubfunctionMapValueMapFdRequirement {
        map_value,
        map_fd,
        call: call.to_string(),
    };
    if !state.map_value_map_fd_requirements.contains(&requirement) {
        state.map_value_map_fd_requirements.push(requirement);
    }
}

fn summary_source_to_requirement(source: SummaryMapSource) -> Option<SubfunctionMapSource> {
    match source {
        SummaryMapSource::Param(idx) if idx < SUMMARY_ARG_SLOTS => {
            Some(SubfunctionMapSource::Arg(idx))
        }
        SummaryMapSource::Param(_) => None,
        SummaryMapSource::Map(map) => Some(SubfunctionMapSource::Map(map)),
    }
}

fn add_iter_delta_arg(
    slots: &mut [Option<IterDeltaState>; SUMMARY_ARG_SLOTS],
    idx: usize,
    family: KfuncIterFamily,
    delta: i8,
) {
    if let Some(slot) = slots.get_mut(idx) {
        *slot = slot.and_then(|state| state.add(family, delta));
    }
}

fn add_unknown_stack_object_delta_arg(
    slots: &mut [Option<UnknownStackObjectDeltaState>; SUMMARY_ARG_SLOTS],
    idx: usize,
    object_type: SubfunctionUnknownStackObjectType,
    delta: i8,
) {
    if let Some(slot) = slots.get_mut(idx) {
        *slot = slot.take().and_then(|state| state.add(object_type, delta));
    }
}

fn set_unknown_stack_object_required_arg(
    args: &mut [Option<SubfunctionUnknownStackObjectType>; SUMMARY_ARG_SLOTS],
    idx: usize,
    object_type: SubfunctionUnknownStackObjectType,
) {
    if idx < SUMMARY_ARG_SLOTS {
        args[idx] = merge_unknown_stack_object_type_option(args[idx].take(), Some(object_type));
    }
}

fn apply_subfunction_release_summary(
    summary: &SubfunctionSummary,
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
            clear_ringbuf_record_source_for_vreg(state, *arg);
            clear_kfunc_ref_source_for_vreg(state, *arg);
        }
        let AliasSource::Param(param_idx) = get_alias(&state.aliases, *arg) else {
            continue;
        };
        if summary.requires_initialized_dynptr_arg(idx) {
            set_mask_bit(&mut state.dynptr_required_args, param_idx);
        }
        let dynptr_delta = summary.dynptr_delta_arg(idx);
        if dynptr_delta != 0 {
            add_delta_arg(&mut state.dynptr_deltas, param_idx, dynptr_delta);
        }
        if summary.maybe_initializes_dynptr_arg(idx) {
            set_mask_bit(&mut state.dynptr_maybe_initialized_args, param_idx);
        }
        if let Some(object_type) = summary.unknown_stack_object_required_arg(idx) {
            set_unknown_stack_object_required_arg(
                &mut state.unknown_stack_object_required,
                param_idx,
                object_type.clone(),
            );
        }
        if let Some(delta) = summary.unknown_stack_object_delta_arg(idx) {
            add_unknown_stack_object_delta_arg(
                &mut state.unknown_stack_object_deltas,
                param_idx,
                delta.object_type.clone(),
                delta.delta,
            );
        }
        if let Some(object_type) = summary.unknown_stack_object_maybe_initialized_arg(idx) {
            set_unknown_stack_object_required_arg(
                &mut state.unknown_stack_object_maybe_initialized,
                param_idx,
                object_type.clone(),
            );
        }
        if summary.releases_ringbuf_record_arg(idx) {
            set_mask_bit(&mut state.ringbuf_record_release_args, param_idx);
        }
        let ringbuf_dynptr_delta = summary.ringbuf_dynptr_delta_arg(idx);
        if ringbuf_dynptr_delta != 0 {
            add_delta_arg(
                &mut state.ringbuf_dynptr_deltas,
                param_idx,
                ringbuf_dynptr_delta,
            );
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
    match helper {
        BpfHelper::RingbufSubmit | BpfHelper::RingbufDiscard => {
            let Some(arg0) = args.first() else {
                return;
            };
            if let MirValue::VReg(arg) = arg0 {
                clear_ringbuf_record_source_for_vreg(state, *arg);
            }
            if let Some(param_idx) = helper_arg_param_alias(args, 0, state, param_stack_aliases) {
                set_mask_bit(&mut state.ringbuf_record_release_args, param_idx);
            }
        }
        BpfHelper::RingbufReserveDynptr => {
            if let Some(param_idx) = helper_arg_param_alias(args, 3, state, param_stack_aliases) {
                add_delta_arg(&mut state.ringbuf_dynptr_deltas, param_idx, 1);
            }
        }
        BpfHelper::RingbufSubmitDynptr | BpfHelper::RingbufDiscardDynptr => {
            if let Some(param_idx) = helper_arg_param_alias(args, 0, state, param_stack_aliases) {
                add_delta_arg(&mut state.ringbuf_dynptr_deltas, param_idx, -1);
            }
        }
        _ => {}
    }
    for (arg_idx, _) in args.iter().enumerate() {
        let Some(role) = helper.dynptr_arg_role(arg_idx) else {
            continue;
        };
        let Some(param_idx) = helper_arg_param_alias(args, arg_idx, state, param_stack_aliases)
        else {
            continue;
        };
        match role {
            HelperDynptrArgRole::In => set_mask_bit(&mut state.dynptr_required_args, param_idx),
            HelperDynptrArgRole::Out => add_delta_arg(&mut state.dynptr_deltas, param_idx, 1),
            HelperDynptrArgRole::RingbufReservationOut
            | HelperDynptrArgRole::RingbufReservationRelease => {}
        }
    }
    if let Some(kind) = helper_release_ref_kind(helper) {
        let Some(arg0) = args.first() else {
            return;
        };
        if let MirValue::VReg(arg) = arg0 {
            clear_kfunc_ref_source_for_vreg(state, *arg);
        }
        if let Some(param_idx) = helper_arg_param_alias(args, 0, state, param_stack_aliases) {
            set_kfunc_release_arg(&mut state.kfunc_ref_release_args, param_idx, kind);
        }
    }
}

fn helper_arg_param_alias(
    args: &[MirValue],
    idx: usize,
    state: &SummaryState,
    param_stack_aliases: &HashMap<super::mir::StackSlotId, usize>,
) -> Option<usize> {
    let arg = args.get(idx)?;
    match alias_for_mir_value(arg, &state.aliases, param_stack_aliases) {
        AliasSource::Param(param_idx) => Some(param_idx),
        AliasSource::Unknown | AliasSource::ContextField(_) => None,
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
    clear_ringbuf_record_source_for_vreg(state, *arg);
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
) -> Option<AliasSource> {
    let value = val?;
    match alias_for_mir_value(value, state, param_stack_aliases) {
        AliasSource::Unknown => None,
        alias => Some(alias),
    }
}

fn ringbuf_record_return_for_value(val: Option<&MirValue>, state: &SummaryState) -> bool {
    let Some(MirValue::VReg(vreg)) = val else {
        return false;
    };
    ringbuf_record_source_for_vreg(state, *vreg).is_some()
}

fn ringbuf_record_source_for_mir_value(value: &MirValue, state: &SummaryState) -> Option<VReg> {
    match value {
        MirValue::VReg(vreg) => ringbuf_record_source_for_vreg(state, *vreg),
        MirValue::StackSlot(_) | MirValue::Const(_) => None,
    }
}

fn ringbuf_record_source_for_vreg(state: &SummaryState, vreg: VReg) -> Option<VReg> {
    state
        .ringbuf_record_sources
        .get(vreg.0 as usize)
        .copied()
        .flatten()
}

fn set_ringbuf_record_source(sources: &mut [Option<VReg>], vreg: VReg, source: Option<VReg>) {
    if let Some(slot) = sources.get_mut(vreg.0 as usize) {
        *slot = source;
    }
}

fn clear_ringbuf_record_source_for_vreg(state: &mut SummaryState, vreg: VReg) {
    let Some(source) = ringbuf_record_source_for_vreg(state, vreg) else {
        return;
    };
    for slot in &mut state.ringbuf_record_sources {
        if *slot == Some(source) {
            *slot = None;
        }
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

fn map_value_source_for_mir_value(
    value: &MirValue,
    state: &SummaryState,
) -> Option<SummaryMapSource> {
    match value {
        MirValue::VReg(vreg) => map_value_source_for_vreg(state, *vreg),
        MirValue::StackSlot(_) | MirValue::Const(_) => None,
    }
}

fn map_value_source_for_vreg(state: &SummaryState, vreg: VReg) -> Option<SummaryMapSource> {
    state
        .map_value_sources
        .get(vreg.0 as usize)
        .cloned()
        .flatten()
}

fn set_map_value_source(
    sources: &mut [Option<SummaryMapSource>],
    vreg: VReg,
    source: Option<SummaryMapSource>,
) {
    if let Some(slot) = sources.get_mut(vreg.0 as usize) {
        *slot = source;
    }
}

fn map_fd_source_for_mir_value(value: &MirValue, state: &SummaryState) -> Option<MapRef> {
    match value {
        MirValue::VReg(vreg) => map_fd_source_for_vreg(state, *vreg),
        MirValue::StackSlot(_) | MirValue::Const(_) => None,
    }
}

fn map_fd_source_for_vreg(state: &SummaryState, vreg: VReg) -> Option<MapRef> {
    state.map_fd_sources.get(vreg.0 as usize).cloned().flatten()
}

fn set_map_fd_source(sources: &mut [Option<MapRef>], vreg: VReg, source: Option<MapRef>) {
    if let Some(slot) = sources.get_mut(vreg.0 as usize) {
        *slot = source;
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
        .cloned()
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
    use crate::compiler::mir::{CtxField, MirFunction, MirInst, MirValue, StackSlotKind};

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
    fn test_infer_summary_tracks_context_field_return_through_nested_subfunction_call() {
        let mut callee = MirFunction::new();
        let callee_entry = callee.alloc_block();
        callee.entry = callee_entry;
        let optval = callee.alloc_vreg();
        callee
            .block_mut(callee_entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: optval,
                field: CtxField::SockoptOptval,
                slot: None,
            });
        callee.block_mut(callee_entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(optval)),
        };

        let mut caller = MirFunction::new();
        let caller_entry = caller.alloc_block();
        caller.entry = caller_entry;
        let ret = caller.alloc_vreg();
        caller
            .block_mut(caller_entry)
            .instructions
            .push(MirInst::CallSubfn {
                dst: ret,
                subfn: SubfunctionId(0),
                args: vec![],
            });
        caller.block_mut(caller_entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(ret)),
        };

        let summaries = infer_subfunction_summaries(&[callee, caller]);
        let callee_summary = summaries
            .get(&SubfunctionId(0))
            .expect("expected callee summary");
        assert_eq!(
            callee_summary.return_context_field(),
            Some(&CtxField::SockoptOptval)
        );
        let caller_summary = summaries
            .get(&SubfunctionId(1))
            .expect("expected caller summary");
        assert_eq!(
            caller_summary.return_context_field(),
            Some(&CtxField::SockoptOptval)
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
            .cloned()
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
            .cloned()
            .expect("expected summary");
        assert!(!summary.releases_ringbuf_record_arg(0));
    }

    #[test]
    fn test_infer_summary_tracks_ringbuf_record_return() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;
        subfn.vreg_count = 1;
        let reserved = subfn.alloc_vreg();
        subfn
            .block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: reserved,
                helper: BpfHelper::RingbufReserve as u32,
                args: vec![
                    MirValue::VReg(VReg(0)),
                    MirValue::Const(8),
                    MirValue::Const(0),
                ],
            });
        subfn.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(reserved)),
        };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .cloned()
            .expect("expected summary");
        assert!(summary.returns_ringbuf_record());
    }

    #[test]
    fn test_infer_summary_does_not_return_released_ringbuf_record() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;
        subfn.vreg_count = 1;
        let reserved = subfn.alloc_vreg();
        let submit_ret = subfn.alloc_vreg();
        subfn
            .block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: reserved,
                helper: BpfHelper::RingbufReserve as u32,
                args: vec![
                    MirValue::VReg(VReg(0)),
                    MirValue::Const(8),
                    MirValue::Const(0),
                ],
            });
        subfn
            .block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: submit_ret,
                helper: BpfHelper::RingbufSubmit as u32,
                args: vec![MirValue::VReg(reserved), MirValue::Const(0)],
            });
        subfn.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(reserved)),
        };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .cloned()
            .expect("expected summary");
        assert!(!summary.returns_ringbuf_record());
    }

    #[test]
    fn test_infer_summary_propagates_nested_ringbuf_dynptr_release_arg() {
        for release_helper in [
            BpfHelper::RingbufSubmitDynptr,
            BpfHelper::RingbufDiscardDynptr,
        ] {
            let mut callee = MirFunction::new();
            let callee_entry = callee.alloc_block();
            callee.entry = callee_entry;
            callee.param_count = 1;
            callee.vreg_count = 1;
            let release_ret = callee.alloc_vreg();
            callee
                .block_mut(callee_entry)
                .instructions
                .push(MirInst::CallHelper {
                    dst: release_ret,
                    helper: release_helper as u32,
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
                .cloned()
                .expect("expected summary");
            assert!(
                summary.releases_ringbuf_dynptr_arg(0),
                "{release_helper:?} should propagate through nested summaries"
            );
            assert!(!summary.releases_ringbuf_dynptr_arg(1));
        }
    }

    #[test]
    fn test_infer_summary_tracks_ringbuf_dynptr_acquire_arg() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;
        subfn.vreg_count = 1;
        let map_slot = subfn.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let reserve_ret = subfn.alloc_vreg();
        subfn
            .block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: reserve_ret,
                helper: BpfHelper::RingbufReserveDynptr as u32,
                args: vec![
                    MirValue::StackSlot(map_slot),
                    MirValue::Const(8),
                    MirValue::Const(0),
                    MirValue::VReg(VReg(0)),
                ],
            });
        subfn.block_mut(entry).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .cloned()
            .expect("expected summary");
        assert_eq!(summary.ringbuf_dynptr_delta_arg(0), 1);
        assert!(!summary.releases_ringbuf_dynptr_arg(0));
    }

    #[test]
    fn test_infer_summary_cancels_balanced_ringbuf_dynptr_lifecycle() {
        for release_helper in [
            BpfHelper::RingbufSubmitDynptr,
            BpfHelper::RingbufDiscardDynptr,
        ] {
            let mut subfn = MirFunction::new();
            let entry = subfn.alloc_block();
            subfn.entry = entry;
            subfn.param_count = 1;
            subfn.vreg_count = 1;
            let map_slot = subfn.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
            let reserve_ret = subfn.alloc_vreg();
            let release_ret = subfn.alloc_vreg();
            subfn
                .block_mut(entry)
                .instructions
                .push(MirInst::CallHelper {
                    dst: reserve_ret,
                    helper: BpfHelper::RingbufReserveDynptr as u32,
                    args: vec![
                        MirValue::StackSlot(map_slot),
                        MirValue::Const(8),
                        MirValue::Const(0),
                        MirValue::VReg(VReg(0)),
                    ],
                });
            subfn
                .block_mut(entry)
                .instructions
                .push(MirInst::CallHelper {
                    dst: release_ret,
                    helper: release_helper as u32,
                    args: vec![MirValue::VReg(VReg(0)), MirValue::Const(0)],
                });
            subfn.block_mut(entry).terminator = MirInst::Return { val: None };

            let summaries = infer_subfunction_summaries(&[subfn]);
            let summary = summaries
                .get(&SubfunctionId(0))
                .cloned()
                .expect("expected summary");
            assert_eq!(
                summary.ringbuf_dynptr_delta_arg(0),
                0,
                "{release_helper:?} should cancel reserve delta"
            );
            assert!(!summary.releases_ringbuf_dynptr_arg(0));
        }
    }

    #[test]
    fn test_infer_summary_tracks_dynptr_required_arg() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;
        subfn.vreg_count = 1;
        let size_ret = subfn.alloc_vreg();
        subfn
            .block_mut(entry)
            .instructions
            .push(MirInst::CallKfunc {
                dst: size_ret,
                kfunc: "bpf_dynptr_size".to_string(),
                btf_id: None,
                args: vec![VReg(0)],
            });
        subfn.block_mut(entry).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .cloned()
            .expect("expected summary");
        assert!(summary.requires_initialized_dynptr_arg(0));
        assert_eq!(summary.dynptr_delta_arg(0), 0);
    }

    #[test]
    fn test_infer_summary_tracks_dynptr_init_arg() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 3;
        subfn.vreg_count = 3;
        let init_ret = subfn.alloc_vreg();
        subfn
            .block_mut(entry)
            .instructions
            .push(MirInst::CallKfunc {
                dst: init_ret,
                kfunc: "bpf_dynptr_from_skb".to_string(),
                btf_id: None,
                args: vec![VReg(0), VReg(1), VReg(2)],
            });
        subfn.block_mut(entry).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .cloned()
            .expect("expected summary");
        assert!(!summary.requires_initialized_dynptr_arg(2));
        assert_eq!(summary.dynptr_delta_arg(2), 1);
        assert!(!summary.maybe_initializes_dynptr_arg(2));
    }

    #[test]
    fn test_infer_summary_tracks_conditional_dynptr_init_arg_as_maybe() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        let init = subfn.alloc_block();
        let done = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 4;
        subfn.vreg_count = 4;
        let init_ret = subfn.alloc_vreg();
        subfn.block_mut(entry).terminator = MirInst::Branch {
            cond: VReg(3),
            if_true: init,
            if_false: done,
        };
        subfn.block_mut(init).instructions.push(MirInst::CallKfunc {
            dst: init_ret,
            kfunc: "bpf_dynptr_from_skb".to_string(),
            btf_id: None,
            args: vec![VReg(0), VReg(1), VReg(2)],
        });
        subfn.block_mut(init).terminator = MirInst::Return { val: None };
        subfn.block_mut(done).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .cloned()
            .expect("expected summary");
        assert_eq!(summary.dynptr_delta_arg(2), 0);
        assert!(summary.maybe_initializes_dynptr_arg(2));
    }

    #[test]
    fn test_infer_summary_tracks_dynptr_copy_args() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 2;
        subfn.vreg_count = 2;
        let clone_ret = subfn.alloc_vreg();
        subfn
            .block_mut(entry)
            .instructions
            .push(MirInst::CallKfunc {
                dst: clone_ret,
                kfunc: "bpf_dynptr_clone".to_string(),
                btf_id: None,
                args: vec![VReg(0), VReg(1)],
            });
        subfn.block_mut(entry).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .cloned()
            .expect("expected summary");
        assert!(summary.requires_initialized_dynptr_arg(0));
        assert_eq!(summary.dynptr_delta_arg(0), 0);
        assert!(!summary.requires_initialized_dynptr_arg(1));
        assert_eq!(summary.dynptr_delta_arg(1), 1);
    }

    #[test]
    fn test_infer_summary_tracks_unknown_stack_object_lifecycle() {
        let mut init = MirFunction::new();
        let init_entry = init.alloc_block();
        init.entry = init_entry;
        init.param_count = 1;
        init.vreg_count = 1;
        let init_ret = init.alloc_vreg();
        init.block_mut(init_entry)
            .instructions
            .push(MirInst::CallKfunc {
                dst: init_ret,
                kfunc: "__test_unknown_stack_object_init".to_string(),
                btf_id: None,
                args: vec![VReg(0)],
            });
        init.block_mut(init_entry).terminator = MirInst::Return { val: None };

        let mut destroy = MirFunction::new();
        let destroy_entry = destroy.alloc_block();
        destroy.entry = destroy_entry;
        destroy.param_count = 1;
        destroy.vreg_count = 1;
        let destroy_ret = destroy.alloc_vreg();
        destroy
            .block_mut(destroy_entry)
            .instructions
            .push(MirInst::CallKfunc {
                dst: destroy_ret,
                kfunc: "__test_unknown_stack_object_destroy".to_string(),
                btf_id: None,
                args: vec![VReg(0)],
            });
        destroy.block_mut(destroy_entry).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[init, destroy]);
        let init_delta = summaries
            .get(&SubfunctionId(0))
            .expect("expected init summary")
            .unknown_stack_object_delta_arg(0)
            .expect("expected init delta");
        assert_eq!(init_delta.object_type.type_name, "bpf_test_obj");
        assert_eq!(init_delta.object_type.type_id, Some(0xbeef));
        assert_eq!(init_delta.delta, 1);

        let destroy_summary = summaries
            .get(&SubfunctionId(1))
            .expect("expected destroy summary");
        let required = destroy_summary
            .unknown_stack_object_required_arg(0)
            .expect("expected required object");
        assert_eq!(required.type_name, "bpf_test_obj");
        let destroy_delta = destroy_summary
            .unknown_stack_object_delta_arg(0)
            .expect("expected destroy delta");
        assert_eq!(destroy_delta.delta, -1);
    }

    #[test]
    fn test_infer_summary_tracks_unknown_stack_object_copy_args() {
        let mut copy = MirFunction::new();
        let entry = copy.alloc_block();
        copy.entry = entry;
        copy.param_count = 2;
        copy.vreg_count = 2;
        let copy_ret = copy.alloc_vreg();
        copy.block_mut(entry).instructions.push(MirInst::CallKfunc {
            dst: copy_ret,
            kfunc: "__test_unknown_stack_object_copy".to_string(),
            btf_id: None,
            args: vec![VReg(0), VReg(1)],
        });
        copy.block_mut(entry).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[copy]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .expect("expected copy summary");
        assert!(summary.unknown_stack_object_required_arg(0).is_some());
        assert!(summary.unknown_stack_object_required_arg(1).is_none());
        assert!(summary.unknown_stack_object_delta_arg(0).is_none());
        let dst_delta = summary
            .unknown_stack_object_delta_arg(1)
            .expect("expected dst delta");
        assert_eq!(dst_delta.object_type.type_name, "bpf_test_obj");
        assert_eq!(dst_delta.delta, 1);
    }

    #[test]
    fn test_infer_summary_tracks_conditional_unknown_stack_object_init_as_maybe() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        let init = subfn.alloc_block();
        let done = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 2;
        subfn.vreg_count = 2;
        subfn.block_mut(entry).terminator = MirInst::Branch {
            cond: VReg(1),
            if_true: init,
            if_false: done,
        };
        let init_ret = subfn.alloc_vreg();
        subfn.block_mut(init).instructions.push(MirInst::CallKfunc {
            dst: init_ret,
            kfunc: "__test_unknown_stack_object_init".to_string(),
            btf_id: None,
            args: vec![VReg(0)],
        });
        subfn.block_mut(init).terminator = MirInst::Return { val: None };
        subfn.block_mut(done).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries.get(&SubfunctionId(0)).expect("expected summary");
        assert!(summary.unknown_stack_object_delta_arg(0).is_none());
        let maybe = summary
            .unknown_stack_object_maybe_initialized_arg(0)
            .expect("expected maybe initialized object");
        assert_eq!(maybe.type_name, "bpf_test_obj");
        assert_eq!(maybe.type_id, Some(0xbeef));
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
            .cloned()
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
            .cloned()
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
            .cloned()
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
            .cloned()
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
            .cloned()
            .expect("expected summary");
        assert_eq!(summary.kfunc_ref_return_kind(), None);
    }

    #[test]
    fn test_infer_summary_tracks_rcu_delta() {
        let mut acquire = MirFunction::new();
        let acquire_entry = acquire.alloc_block();
        acquire.entry = acquire_entry;
        let acquire_ret = acquire.alloc_vreg();
        acquire
            .block_mut(acquire_entry)
            .instructions
            .push(MirInst::CallKfunc {
                dst: acquire_ret,
                kfunc: "bpf_rcu_read_lock".to_string(),
                btf_id: None,
                args: vec![],
            });
        acquire.block_mut(acquire_entry).terminator = MirInst::Return { val: None };

        let mut release = MirFunction::new();
        let release_entry = release.alloc_block();
        release.entry = release_entry;
        let release_ret = release.alloc_vreg();
        release
            .block_mut(release_entry)
            .instructions
            .push(MirInst::CallKfunc {
                dst: release_ret,
                kfunc: "bpf_rcu_read_unlock".to_string(),
                btf_id: None,
                args: vec![],
            });
        release.block_mut(release_entry).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[acquire, release]);
        assert_eq!(
            summaries
                .get(&SubfunctionId(0))
                .cloned()
                .expect("expected acquire summary")
                .rcu_read_lock_delta(),
            1
        );
        assert_eq!(
            summaries
                .get(&SubfunctionId(1))
                .cloned()
                .expect("expected release summary")
                .rcu_read_lock_delta(),
            -1
        );
    }

    #[test]
    fn test_infer_summary_requires_rcu_delta_on_all_returns() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        let acquire = subfn.alloc_block();
        let done = subfn.alloc_block();
        subfn.entry = entry;
        subfn.vreg_count = 1;
        subfn.block_mut(entry).terminator = MirInst::Branch {
            cond: VReg(0),
            if_true: acquire,
            if_false: done,
        };
        let acquire_ret = subfn.alloc_vreg();
        subfn
            .block_mut(acquire)
            .instructions
            .push(MirInst::CallKfunc {
                dst: acquire_ret,
                kfunc: "bpf_rcu_read_lock".to_string(),
                btf_id: None,
                args: vec![],
            });
        subfn.block_mut(acquire).terminator = MirInst::Return { val: None };
        subfn.block_mut(done).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .cloned()
            .expect("expected summary");
        assert_eq!(summary.rcu_read_lock_delta(), 0);
    }

    #[test]
    fn test_infer_summary_tracks_preempt_delta() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        subfn.entry = entry;
        let ret = subfn.alloc_vreg();
        subfn
            .block_mut(entry)
            .instructions
            .push(MirInst::CallKfunc {
                dst: ret,
                kfunc: "bpf_preempt_disable".to_string(),
                btf_id: None,
                args: vec![],
            });
        subfn.block_mut(entry).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .cloned()
            .expect("expected summary");
        assert_eq!(summary.preempt_disable_delta(), 1);
    }

    #[test]
    fn test_infer_summary_tracks_local_irq_arg_delta() {
        let mut save = MirFunction::new();
        let save_entry = save.alloc_block();
        save.entry = save_entry;
        save.param_count = 1;
        save.vreg_count = 1;
        let save_ret = save.alloc_vreg();
        save.block_mut(save_entry)
            .instructions
            .push(MirInst::CallKfunc {
                dst: save_ret,
                kfunc: "bpf_local_irq_save".to_string(),
                btf_id: None,
                args: vec![VReg(0)],
            });
        save.block_mut(save_entry).terminator = MirInst::Return { val: None };

        let mut restore = MirFunction::new();
        let restore_entry = restore.alloc_block();
        restore.entry = restore_entry;
        restore.param_count = 1;
        restore.vreg_count = 1;
        let restore_ret = restore.alloc_vreg();
        restore
            .block_mut(restore_entry)
            .instructions
            .push(MirInst::CallKfunc {
                dst: restore_ret,
                kfunc: "bpf_local_irq_restore".to_string(),
                btf_id: None,
                args: vec![VReg(0)],
            });
        restore.block_mut(restore_entry).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[save, restore]);
        assert_eq!(
            summaries
                .get(&SubfunctionId(0))
                .cloned()
                .expect("expected save summary")
                .local_irq_delta_arg(0),
            1
        );
        assert_eq!(
            summaries
                .get(&SubfunctionId(1))
                .cloned()
                .expect("expected restore summary")
                .local_irq_delta_arg(0),
            -1
        );
    }

    #[test]
    fn test_infer_summary_requires_local_irq_delta_on_all_returns() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        let save = subfn.alloc_block();
        let done = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;
        subfn.vreg_count = 2;
        subfn.block_mut(entry).terminator = MirInst::Branch {
            cond: VReg(1),
            if_true: save,
            if_false: done,
        };
        let save_ret = subfn.alloc_vreg();
        subfn.block_mut(save).instructions.push(MirInst::CallKfunc {
            dst: save_ret,
            kfunc: "bpf_local_irq_save".to_string(),
            btf_id: None,
            args: vec![VReg(0)],
        });
        subfn.block_mut(save).terminator = MirInst::Return { val: None };
        subfn.block_mut(done).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .cloned()
            .expect("expected summary");
        assert_eq!(summary.local_irq_delta_arg(0), 0);
    }

    #[test]
    fn test_infer_summary_tracks_iter_delta() {
        let mut new = MirFunction::new();
        let new_entry = new.alloc_block();
        new.entry = new_entry;
        new.param_count = 1;
        new.vreg_count = 1;
        let start = new.alloc_vreg();
        let end = new.alloc_vreg();
        let new_ret = new.alloc_vreg();
        new.block_mut(new_entry)
            .instructions
            .push(MirInst::CallKfunc {
                dst: new_ret,
                kfunc: "bpf_iter_num_new".to_string(),
                btf_id: None,
                args: vec![VReg(0), start, end],
            });
        new.block_mut(new_entry).terminator = MirInst::Return { val: None };

        let mut destroy = MirFunction::new();
        let destroy_entry = destroy.alloc_block();
        destroy.entry = destroy_entry;
        destroy.param_count = 1;
        destroy.vreg_count = 1;
        let destroy_ret = destroy.alloc_vreg();
        destroy
            .block_mut(destroy_entry)
            .instructions
            .push(MirInst::CallKfunc {
                dst: destroy_ret,
                kfunc: "bpf_iter_num_destroy".to_string(),
                btf_id: None,
                args: vec![VReg(0)],
            });
        destroy.block_mut(destroy_entry).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[new, destroy]);
        let new_delta = summaries
            .get(&SubfunctionId(0))
            .cloned()
            .expect("expected new summary")
            .iter_delta_arg(0)
            .expect("expected iterator delta");
        assert_eq!(new_delta.family, KfuncIterFamily::Num);
        assert_eq!(new_delta.delta, 1);
        let destroy_delta = summaries
            .get(&SubfunctionId(1))
            .cloned()
            .expect("expected destroy summary")
            .iter_delta_arg(0)
            .expect("expected iterator delta");
        assert_eq!(destroy_delta.family, KfuncIterFamily::Num);
        assert_eq!(destroy_delta.delta, -1);
    }

    #[test]
    fn test_infer_summary_requires_iter_delta_on_all_returns() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        let new = subfn.alloc_block();
        let done = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;
        subfn.vreg_count = 2;
        subfn.block_mut(entry).terminator = MirInst::Branch {
            cond: VReg(1),
            if_true: new,
            if_false: done,
        };
        let start = subfn.alloc_vreg();
        let end = subfn.alloc_vreg();
        let new_ret = subfn.alloc_vreg();
        subfn.block_mut(new).instructions.push(MirInst::CallKfunc {
            dst: new_ret,
            kfunc: "bpf_iter_num_new".to_string(),
            btf_id: None,
            args: vec![VReg(0), start, end],
        });
        subfn.block_mut(new).terminator = MirInst::Return { val: None };
        subfn.block_mut(done).terminator = MirInst::Return { val: None };

        let summaries = infer_subfunction_summaries(&[subfn]);
        let summary = summaries
            .get(&SubfunctionId(0))
            .cloned()
            .expect("expected summary");
        assert_eq!(summary.iter_delta_arg(0), None);
    }
}
